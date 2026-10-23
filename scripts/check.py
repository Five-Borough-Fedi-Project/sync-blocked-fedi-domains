#!/usr/bin/env python3
"""Decide whether a blocklist update can apply itself.

The instance is the state. There is no committed copy of the blocklist to diff
against: what masto.nyc currently blocks is whatever /api/v1/admin/domain_blocks
says it blocks, and this compares the freshly merged lists against that.

Four verdicts, on stdout as `verdict=...` for the workflow to read:

  ok       the delta is routine. Apply it.
  review   the delta is anomalously large. Do not apply; a human looks first.
  fail     the fetched data is not trustworthy. Do not apply, and do not
           pretend a human could usefully review it either.
  error    the data is fine but the instance could not answer a question the
           decision needs. Do not apply.

The distinction between `review` and `fail` is the point. A bad fetch from
Google Sheets produces a small or empty list, which is a `fail`: there is
nothing to review, the input is broken. A genuine week where IFTAS adds forty
domains is a `review`: the input is fine and the decision is a moderator's.

Writes the rows that should actually be pushed to APPLICABLE_CSV, which is
the merged list minus the marker rows. The apply step reads that file and not
the raw merge, so a canary can never reach the instance.

It also asks the instance the question fediblockhole will ask before it
suspends anything, so that a suspend the follow guard is going to refuse is not
reported as a change. That needs TOKEN in the environment.

Usage: check.py CANDIDATE_CSV INSTANCE_JSON APPLICABLE_CSV REMOVE_TSV
"""
import csv
import json
import os
import sys
import urllib.error
import urllib.request

# Each IFTAS list carries its own marker row, in a TLD that cannot resolve, named
# after the list. Verified against the live sheets on 2026-10-12:
#
#   dni.invalid     DNI          95 rows
#   aud.invalid     AUD          49 rows
#   cariad.invalid  CARIAD 66%  115 rows
#
# All three are asserted, not just one, because they are a *per-list* integrity
# check and nothing else in here is. A sheet that answers with an HTML error page
# under throttling yields no rows, and losing one list means fewer additions
# proposed -- so a partial fetch makes the size gate *more* likely to say `ok`
# and apply. Checking a single marker would let two thirds of the input vanish
# silently with every other guard satisfied; MIN_ROWS would not catch it either,
# since any two of these lists together clear it comfortably.
#
# Keep this in step with blocklist_url_sources in sources.toml. A list added
# without its marker here is a list whose disappearance nobody would notice.
CANARIES = {"dni.invalid", "aud.invalid", "cariad.invalid"}

# ...and then every one of them has to be thrown away. They are proof the fetch
# worked, not domains anybody federates with, and fediblockhole has no code path
# that deletes a block -- pushing one would park it in the moderation table
# forever.
#
# Stripped by TLD rather than against CANARIES above, so that a list added to
# sources.toml without its marker being registered here still cannot leak that
# marker onto the instance. The two checks fail independently and in opposite
# directions: CANARIES catches a marker that should be present and is not, this
# catches one that is present and should not be applied.
# RFC 2606 reserves `.invalid` precisely so that nothing can ever resolve there,
# so a real instance cannot be caught by this.
RESERVED_TLD = ".invalid"

# A floor, not an estimate. The three lists merged to 204 domains on 2026-10-09.
# Fifty is far below any plausible shrinkage and far above a truncated sheet or
# an error page.
MIN_ROWS = 50

# What counts as anomalous. Additions above *either* of these needs a person.
#
# The lists move weekly at most and a week's change is a handful of domains, so
# ten is already unusual. The percentage is there for the case the absolute
# number is not: on an instance blocking very little, ten additions is a large
# proportional change, and on one blocking a lot it is noise. Whichever is
# larger wins, so neither alone can make the gate absurd.
MAX_NEW_ABSOLUTE = 10
MAX_NEW_PCT = 10.0

# Lifting a block is the direction that reduces protection, so it gets a
# tighter rail than the ceiling above rather than sharing it. At 621 blocks the
# ceiling is 62, and sixty-two silent un-blockings is not something this job
# should be able to do on a schedule.
#
# Only allowlisted domains are ever candidates for lifting. Not `gone` -- the
# domains that left the upstream lists -- because that set includes every block
# masto.nyc made for its own reasons: moderator decisions, user reports, and the
# oliphant-era entries that predate this repository. The allowlist is the only
# list here that is an explicit, reviewed, version-controlled statement that a
# domain should not be blocked, which is what makes it safe to act on.
MAX_REMOVALS_AUTO = 5

EXPECTED_HEADER = ["domain", "severity", "public_comment"]

# Ordered least to most severe, for spotting escalations. fediblockhole will
# raise an existing block's severity; it never lowers one and never deletes.
SEVERITY_RANK = {"noop": 0, "silence": 1, "suspend": 2}

# Must match max_followed_severity on the destination in sync.yaml. Above this,
# fediblockhole asks /api/v1/admin/measures how many local accounts follow
# somebody on the domain, and caps the block here if any do.
#
# Leaving that out of the diff is what announced "silence -> suspend" for
# channels.im, elonsucks.org and theater.im to Discord every morning (run
# 39943392258 among them): the push asked, found followers, kept them at
# silence, and the next run proposed the same three again. A change the guard
# will refuse is not a change.
MAX_FOLLOWED_SEVERITY = "silence"


def read_candidate(path):
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != EXPECTED_HEADER:
            raise ValueError(
                "header is %r, expected %r. A Google Sheets error page and a "
                "changed sources.toml both look like this."
                % (reader.fieldnames, EXPECTED_HEADER)
            )
        return {r["domain"]: r for r in reader if r.get("domain")}


def write_applicable(path, candidate):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPECTED_HEADER)
        writer.writeheader()
        for domain in sorted(candidate):
            row = candidate[domain]
            writer.writerow({k: row.get(k, "") for k in EXPECTED_HEADER})


def read_allowlist():
    # Resolved from this file's location, not the working directory. A
    # cwd-relative lookup that silently found nothing would turn the allowlist
    # check into a no-op, which is the one way it must not fail.
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "allowlist.csv",
    )
    if not os.path.exists(path):
        raise ValueError("no allowlist at %s" % path)
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["domain"] for r in csv.DictReader(fh) if r.get("domain")}


def read_instance(path):
    """Current blocks, as the admin API reports them."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(
            "instance blocks are %s, not a list. An API error body looks like "
            "this." % type(data).__name__
        )
    return {b["domain"]: b for b in data if b.get("domain")}


def instance_follows(domain):
    """Local follows of accounts at `domain`, exactly as fediblockhole counts them.

    Same endpoint, same measure, same body as fetch_instance_follows in
    fediblockhole 0.4.6. A different question here would let this report a
    change the push then declines, which is the bug this exists to fix.
    """
    req = urllib.request.Request(
        "https://masto.nyc/api/v1/admin/measures",
        data=json.dumps({
            "keys": ["instance_follows"],
            "instance_follows": {"domain": domain},
        }).encode(),
        headers={
            "Authorization": "Bearer " + os.environ["TOKEN"],
            "Content-Type": "application/json",
            "User-Agent": "masto.nyc blocklist-sync",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return int(json.load(resp)[0]["total"])


def effective_severity(domain, severity, follows):
    """What fediblockhole will actually push for this domain."""
    cap = MAX_FOLLOWED_SEVERITY
    if SEVERITY_RANK.get(severity, 0) <= SEVERITY_RANK[cap]:
        return severity
    if domain not in follows:
        follows[domain] = instance_follows(domain)
    return cap if follows[domain] > 0 else severity


def main(argv):
    if len(argv) != 5:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    try:
        candidate = read_candidate(argv[1])
        allowed = read_allowlist()
        current = read_instance(argv[2])
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print("reason: %s" % exc)
        print("verdict=fail")
        return 1

    print("candidate: %d domains" % len(candidate))
    print("instance:  %d domains currently blocked" % len(current))

    hard = []
    if len(candidate) < MIN_ROWS:
        hard.append(
            "only %d domains in the merged list, floor is %d. Suspect a failed "
            "or partial fetch." % (len(candidate), MIN_ROWS)
        )
    missing = sorted(CANARIES - set(candidate))
    if missing:
        hard.append(
            "marker row(s) %s missing from the merged list. Each list carries "
            "exactly one, so a missing marker means that whole list failed to "
            "fetch and its domains are absent." % ", ".join(missing)
        )
    leaked = sorted(allowed & set(candidate))
    if leaked:
        hard.append(
            "allowlisted domains survived the merge: %s. The allowlist was not "
            "applied." % ", ".join(leaked)
        )

    if hard:
        for h in hard:
            print("reason: %s" % h)
        print("verdict=fail")
        return 1

    print("allowlist: %d entries, none present in the merged list" % len(allowed))

    # Allowlisted domains the instance still blocks. The allowlist says these
    # should not be blocked; until now it could only stop them being re-added,
    # which left "allowed" and "blocked" true at the same time.
    remove = sorted(allowed & set(current))
    with open(argv[4], "w", encoding="utf-8") as fh:
        for domain in remove:
            block_id = current[domain].get("id")
            if not block_id:
                # Without an id there is nothing to DELETE. Say so rather than
                # dropping it silently.
                print("reason: %s is allowlisted and blocked, but the admin API "
                      "gave no id for the block, so it cannot be lifted." % domain)
                continue
            fh.write("%s\t%s\n" % (block_id, domain))

    markers = sorted(d for d in candidate if d.endswith(RESERVED_TLD))
    for d in markers:
        del candidate[d]
    print("dropped %d list marker(s) in %s: %s" % (
        len(markers), RESERVED_TLD, ", ".join(markers) or "none"))
    write_applicable(argv[3], candidate)

    # What applying would actually do. Removals are listed for information
    # only: fediblockhole has no code path that deletes a domain block, so a
    # domain leaving the upstream lists stays blocked here until a person
    # removes it by hand.
    #
    # Severities are the ones the push will really use: anything above
    # MAX_FOLLOWED_SEVERITY is checked for local follows first, as fediblockhole
    # does. An escalation that ends up where it already is goes under `held`
    # rather than `escalations`, so it is neither counted nor announced.
    follows = {}
    try:
        new = sorted(set(candidate) - set(current))
        pushed = {d: effective_severity(d, candidate[d]["severity"], follows)
                  for d in new}
        escalations, held = [], []
        for d in sorted(set(candidate) & set(current)):
            was = SEVERITY_RANK.get(current[d].get("severity", "noop"), 0)
            if SEVERITY_RANK.get(candidate[d]["severity"], 0) <= was:
                continue
            pushed[d] = effective_severity(d, candidate[d]["severity"], follows)
            if SEVERITY_RANK.get(pushed[d], 0) > was:
                escalations.append(d)
            else:
                held.append(d)
    except (urllib.error.URLError, OSError, KeyError, IndexError, ValueError) as exc:
        # The push would hit the same wall on its first suspend. Stopping here
        # changes nothing, which is the better place to find out.
        #
        # `error`, not `fail`: the lists are fine, the instance did not answer.
        # `fail` would have Discord blame the lists for it.
        print("reason: could not ask masto.nyc who follows the domains about to "
              "be suspended (%s). The follow guard depends on that answer, and "
              "the token needs admin:read for it." % exc)
        print("verdict=error")
        return 1
    gone = sorted(set(current) - set(candidate))

    def note(d):
        if pushed[d] == candidate[d]["severity"]:
            return ""
        return "; %s held back, %d local follow(s)" % (candidate[d]["severity"], follows[d])

    print("would add: %d" % len(new))
    print("would raise severity on: %d" % len(escalations))
    print("held at their current severity by local follows: %d" % len(held))
    print("no longer listed upstream (left alone): %d" % len(gone))
    for d in new:
        print("  + %s (%s%s)" % (d, pushed[d], note(d)))
    for d in escalations:
        print("  ^ %s (%s -> %s%s)" % (d, current[d].get("severity"), pushed[d], note(d)))
    # Not a `+`, `^` or `-` line, so the workflow neither counts it nor sends it
    # to Discord. It stays in the run summary for whoever wants to know why a
    # listed domain is only silenced.
    for d in held:
        print("  = %s (stays %s; %s held back, %d local follow(s))" % (
            d, current[d].get("severity"), candidate[d]["severity"], follows[d]))
    print("would lift the block on: %d" % len(remove))
    for d in remove:
        print("  - %s (currently %s, allowlisted)" % (d, current[d].get("severity")))

    # The gate is on additions and escalations together, since both change what
    # federation does. Removals cannot be acted on, so they cannot be anomalous.
    changes = len(new) + len(escalations) + len(remove)
    ceiling = max(MAX_NEW_ABSOLUTE, int(len(current) * MAX_NEW_PCT / 100.0))
    print("changes: %d, ceiling: %d" % (changes, ceiling))

    if len(remove) > MAX_REMOVALS_AUTO:
        print(
            "reason: %d blocks would be lifted, over the limit of %d for an "
            "unattended run. Lifting a block reduces protection, so a person "
            "confirms it however small the overall change is."
            % (len(remove), MAX_REMOVALS_AUTO)
        )
        print("verdict=review")
        return 0

    if changes == 0:
        print("verdict=ok")
        print("nothing to do")
        return 0

    if changes > ceiling:
        print(
            "reason: %d changes is over the ceiling of %d (the larger of %d and "
            "%.0f%% of the %d currently blocked). Not applying this without a "
            "person." % (changes, ceiling, MAX_NEW_ABSOLUTE, MAX_NEW_PCT, len(current))
        )
        print("verdict=review")
        return 0

    print("verdict=ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
