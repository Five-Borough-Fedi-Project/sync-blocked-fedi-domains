# sync-blocked-fedi-domains

Keeps [masto.nyc](https://masto.nyc)'s federation blocks in step with the
[IFTAS denylists](https://about.iftas.org/library/denylist-resources/).

Routine updates apply themselves. A person is pulled in only when a change is
unusually large, or when the fetched data cannot be trusted.

Not to be confused with
[sync-blocked-email-domains](https://github.com/Five-Borough-Fedi-Project/sync-blocked-email-domains),
which blocks **email** domains at signup. Different problem, similar name; the
two have been mixed up before.

## Allowing a domain

Edit [`allowlist.csv`](allowlist.csv). Anything listed there is dropped from the
merged list no matter which source proposed it, and this is the only file here
you should expect to edit by hand.

```csv
domain,severity,public_comment
masto.nyc,noop,"Never block ourselves."
threads.net,noop,"Moderator decision, 2026-10-09."
```

`severity` and `public_comment` are for whoever reads the diff later;
fediblockhole only reads `domain`. Say *why* in the comment — in a year it is
the only record of the decision.

More than five blocks lifted in one run is held for review whatever the
overall change size, because lifting is the direction that reduces protection.
Allowlisting a batch therefore needs one `allow_large_change` dispatch, which
is the point: somebody reads the list before federation reopens.

Two things to know:

- **Matching is exact.** An entry for `example.com` does not cover
  `social.example.com`. These lists carry root domains so that is fine in
  practice, but a list adding a subdomain variant needs its own row.
- **Adding an entry lifts the block.** If a domain you allowlist is already
  blocked, the next approved run removes that block. This is the only thing
  here that ever un-blocks anything, and the allowlist is the only input it
  will act on: a domain that merely dropped off the upstream lists stays
  blocked, because that set also holds every block made by a moderator, from a
  report, or inherited from the oliphant era.
- **Removing an entry does not re-block anything by itself.** Taking a domain
  out of the allowlist just means the next run is free to block it again if a
  source still lists it.

## What it subscribes to

| list | domains | what it is |
|---|---|---|
| DNI | 95 | IFTAS's curated "do not interact" set |
| AUD | 49 | spammers and abandoned servers |
| CARIAD 66% | 115 | blocked by two thirds of the network IFTAS observes |
| **merged, minus the allowlist** | **204** | what gets pushed |

Counts as of 2026-10-09.

66% is the chosen threshold because it is a number you can be held to. "We
defederate what two thirds of the observed network defederates" is checkable;
"we use somebody's list" is not. IFTAS also publishes 51% and 80% tiers, and
[`sources.toml`](sources.toml) carries the 51% URL in a comment — swapping it
makes this equivalent to IFTAS's Omnibus file, at 289 domains.

### Why IFTAS and not the alternatives

The job this replaces subscribed to oliphant's Tier 0 list. That list has not
changed since 2026-03-29 and the repository behind it has had no commit since
2026-04-15, so restoring the old job as written would have pinned the instance
to a blocklist frozen in March.

Garden Fence was the next candidate and is better maintained, but had not
published since 2026-08-09 against a stated weekly cadence, and is explicitly
one instance's judgement: only domains blocked by sunny.garden, filtered through
unnamed reference servers. Its README says so plainly.

IFTAS is an organisation rather than an admin, was posting in September 2026,
and publishes its thresholds as numbers.

## How a run decides

Nothing is stored. What this instance blocks is whatever
`/api/v1/admin/domain_blocks` says it blocks, and the merged lists are compared
against that. `scripts/check.py` returns one of three verdicts.

**`ok` — apply it.** Additions and severity escalations within the gate go
straight in, and Discord gets the diff.

**`review` — the data is fine, the decision is a moderator's.** Nothing is
applied, Discord is told, and the run goes red so a held decision does not look
like success. Triggered when additions plus escalations exceed the larger of
**10** and **10% of what the instance currently blocks**.

Ten because these lists move weekly at most and a week's change is a handful of
domains. The percentage because ten is the wrong measure at both extremes: a
large proportional change on an instance blocking little, noise on one blocking
a lot.

To accept a held change, re-run the workflow with `allow_large_change`. That
re-fetches rather than replaying, so a stale approval applies today's list
rather than the one in the run you read.

**`fail` — the data is not trustworthy.** Nothing is applied and nobody is asked
to review it, because there is nothing worth reviewing. Triggered by a wrong
header, fewer than 50 domains, a missing canary, an allowlisted domain surviving
the merge, or an admin API response that is not a list of blocks.

IFTAS serves these lists from Google Sheets, which sends `no-store`, no `ETag`,
and can hand back an HTML error page when throttled. `fail` and `review` are
deliberately separate: an error page is a broken input, not a moderation
decision, and routing it to a person wastes attention on something with no
signal in it.

## What it will not do

**It never unblocks anything.** fediblockhole has a `delete_block` function and
no code path that calls it. A domain dropping off the upstream lists stays
blocked here until a person removes it. That is also why a shrinking upstream
list can never trip the size gate.

**It never suspends a domain somebody here follows.** The destination carries
`max_followed_severity = 'silence'`. Every row in all three lists is `suspend`,
and a suspend severs existing follow relationships; this caps it at silence
where a follow exists. It is the single setting that makes automating this
defensible.

## Confirming it ran

Ask the instance for the canary. Every IFTAS list carries a block on
`cariad.invalid`, a domain in an invalid TLD that exists only to be a sentinel.
If it appears under **Moderation > Federation**, a push landed.

Discord gets a message whenever something happened, carrying the diff:

```
**Blocklist updated**: 3 applied to masto.nyc.
  + newbadsite.example (suspend)
  + another.example (suspend)
  ^ known.example (silence -> suspend)
```

A day with no changes says nothing at all. A channel that gets a daily "nothing
to report" is a channel that gets muted. The headline is keyed on whether the
push actually succeeded rather than on the verdict, so a partial apply says so
instead of claiming success.

## Setup

Two repository secrets:

| secret | why |
|---|---|
| `MASTODON_ADMIN_TOKEN` | needs `admin:read`, `admin:read:domain_blocks` and `admin:write:domain_blocks`. Read is not optional: without it there is nothing to compare against, so the job logs a notice and exits 0. The broad `admin:read` is there for `max_followed_severity` (see below), and the apply step pre-flights it rather than discovering it halfway through a push. |
| `DISCORD_OPS_WEBHOOK` | the ops channel. Without it the sync still runs and still applies; it just says nothing. |

The token is a secret rather than a config value on purpose. The job this
replaces put it inline in a TOML file inside a Kubernetes ConfigMap, where
`kubectl describe` would print it.

### Why the token needs `admin:read`

`max_followed_severity = 'silence'` is the guard that stops a suspend severing
follow relationships somebody here already has. fediblockhole implements it by
asking `/api/v1/admin/measures` for the `instance_follows` count of each domain
before it blocks or escalates one, and that endpoint is gated on `admin:read` --
not on the granular `admin:read:domain_blocks`.

So the token reads more than it writes. It can read anything the admin API
exposes, and write nothing but domain blocks. That is a deliberate trade: the
alternative is dropping the guard, which means suspending general-population
instances outright and cutting existing follows without warning.

Every row in these lists is `suspend`, and `check_followed_severity` only skips
the lookup when the new severity is at or below `max_followed_severity`. So the
lookup happens for every addition and every escalation -- it is not an edge
case, and a token without the scope fails on the first one.

## Why its own repository

The infrastructure lives in
[masto.nyc-docean](https://github.com/Five-Borough-Fedi-Project/masto.nyc-docean),
and this used to live there too. It moved for two reasons.

`allowlist.csv` is a moderation artifact. Editing it should not require write
access to a repository that can deploy Kubernetes, apply Terraform against
DigitalOcean and rotate database credentials.

And the admin token belongs somewhere narrower than a secret store that also
holds the DigitalOcean, Cloudflare and Spaces credentials, readable by every
workflow in that repository.

Nothing here touches the cluster. It talks to the Mastodon admin API over HTTPS,
so a runner and a pip install are the whole dependency — unlike the original,
which needed an unpinned image from a private third-party registry and did not
survive a migration because of it.

`renovate.json` exists for the same reason. Three files and a workflow is
exactly the kind of thing that rots quietly, and the pins are only worth
anything if something keeps them current.
