# Missouri American Water (MyWater) — Home Assistant Integration

[![HACS Custom Repository](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Home Assistant integration for **Missouri American Water**'s MyWater customer
portal (`mywaterv2.amwater.com`), pulling hourly and daily water usage
(gallons) into Home Assistant — including long-term statistics compatible
with the **Energy dashboard**'s water source. Because MyWater's meter sits
at the property line, this gives you **whole-property usage tracking**
(house, irrigation, outbuildings, everything on that meter). If you also
have a home-only device like a Flo/Moen valve, this integration can combine
the two to distinguish **home usage** from everything else outside the main
line (see [Options](#options-home-vs-outside-the-home-usage-breakdown)
below).

> **Unofficial project.** This is a reverse-engineered integration built by
> inspecting MyWater's own web app network traffic. It is **not affiliated
> with, endorsed by, or supported by American Water Works Company, Inc.** or
> Missouri American Water. Use at your own risk — see [Disclaimer](#disclaimer)
> below. The Missouri American Water name/logo included in `brand/` is used
> only for local Home Assistant UI recognition on your own instance; do not
> redistribute this repository as an official or HACS-default-store
> integration without the trademark owner's permission.

---

## How it works

MyWater's frontend is built on **AppOrchid Vulcanx** and authenticates via
**Okta's Identity Engine (IDX) API**, with account data served from a
generic `/api/mso/data` "Model-Service-Object" endpoint. There is no public
API — this integration replicates the exact sequence of calls the browser
makes:

1. **Login (Okta IDX flow)** — `identify` (username) → `challenge/answer`
   (password) →, if MFA is enabled, `challenge` (select factor) →
   `challenge/answer` (one-time passcode) → a redirect chain that lands back
   on `mywaterv2.amwater.com/openidlogin`, where MyWater's backend mints the
   session (`mw_id_token` cookie) used as a bearer token for all API calls.
2. **Account discovery** — a `customer_profile_pipeline` MSO call returns
   your `businessPartnerNumber`, `connectionContractNumber`, and `premiseId`,
   which every usage request needs.
3. **Usage data** — `POST /api/mso/data` with a `microApplicationId` selecting
   the chart granularity:

   | Portal view | `microApplicationId` |
   |---|---|
   | 24 Hours  | `usageOverviewHourlyChart` |
   | 30 Days   | `usageOverviewDailyChart` |
   | 12 Months | `usageOverview12MonthlyChart` |
   | 24 Months | `usageOverview24MonthlyChart` |
   | 36 Months | `usageOverviewMonthlyChartFourYears` |

   The response embeds a Highcharts-style `series`/`categories` payload;
   this integration extracts the `"Actual Usage"` series (gallons) for each
   period.

### Multi-Factor Authentication (MFA)

You do **not** need to disable MFA on your account. The config flow has a
dedicated second step: if Okta challenges the login with a one-time code
(SMS, email, or authenticator app), Home Assistant will show a second form
asking you to enter it — same UX pattern as other MFA-protected integrations
(e.g. Ring). Once linked, MyWater's session is refreshed automatically on
each restart using your stored username/password; if Okta ever demands a
fresh MFA challenge again (e.g. due to risk-based re-authentication), Home
Assistant will surface a "reauthenticate" notification for you to complete
the MFA step again.

MoAmWater's Okta tenant enforces a hard ~23hr absolute session lifetime that
no amount of keep-alive activity can extend, and MFA for this account is
SMS-only — so a reauth roughly once a day is effectively unavoidable, and
the code always arrives by text. Two services,
`moamwater.start_reauth`/`moamwater.submit_mfa_code`, let an automation
finish that reauth for you automatically instead of tapping through the UI
form every day:

1. The integration itself calls `start_reauth` automatically the instant it
   detects the session is dead, which triggers Okta's SMS immediately — you
   don't need to call this yourself in the common case.
2. Set up a way to read that SMS automatically and call
   `moamwater.submit_mfa_code` with the code.

#### iPhone: a ready-made Shortcut (no third-party app needed)

A working [Shortcuts automation](https://www.icloud.com/shortcuts/d8aa7fd5a93e4ebba1416ff01696966f)
is available to import directly — it reads the incoming MFA text and posts
the code to an HA webhook. Importing it will ask you for your own webhook
URL (nothing of the original author's is baked in).
To set it up:

1. Open the link above on your iPhone and import it as a **personal
   automation** triggered by **Message**, filtered to MoAmWater's sending
   number, with **Ask Before Running** turned off. When prompted, enter
   your own webhook URL, e.g.
   `https://<your-nabu-casa-or-public-ha-url>/api/webhook/<your-webhook-id>`
   — pick your own random-looking webhook ID (treat it like a secret, since
   it's the only thing authenticating the request).
2. Create the matching automation in Home Assistant (Settings →
   Automations → **+ Add Automation** → **Edit in YAML**):

   ```yaml
   alias: MoAmWater - submit MFA code from SMS
   description: >-
     Triggered by an HA webhook that an iPhone Shortcut posts to after
     reading the MoAmWater/Okta MFA text. Forwards the code to
     moamwater.submit_mfa_code to finish the automated reauth.
   triggers:
     - trigger: webhook
       webhook_id: <your-webhook-id>   # must match the Shortcut's URL
       allowed_methods:
         - POST
       local_only: false   # required: the Shortcut posts from the internet
   conditions:
     - condition: template
       value_template: >-
         {{ trigger.json is defined and trigger.json.otp is defined
            and trigger.json.otp != '' }}
   actions:
     - action: moamwater.submit_mfa_code
       data:
         code: "{{ trigger.json.otp }}"
         # entry_id: <only needed with more than one MoAmWater account>
   mode: single
   ```

The existing "reauthenticate" UI notification/form still works as a manual
fallback (e.g. if your credentials change, or the automation doesn't fire)
— this setup just races it to the punch, confirmed working end-to-end.

---

## Installation

### Via HACS (custom repository)

1. HACS → Integrations → ⋮ → **Custom repositories**
2. Add `https://github.com/tylermsellers/moamwater-hacs`, category
   **Integration**
3. Install **Missouri American Water (MyWater)**, restart Home Assistant
4. Settings → Devices & Services → **Add Integration** → search
   "Missouri American Water"
5. Enter your MyWater username/password, then the MFA code if prompted

### Manual

Copy `custom_components/moamwater/` into your Home Assistant `config/custom_components/` directory and restart.

---

## Entities created

| Entity | Description |
|---|---|
| `sensor.today_s_water_usage` | Sum of today's hourly usage so far (gallons) |
| `sensor.last_hour_water_usage` | Most recent hour's usage (gallons) |
| `sensor.yesterday_s_water_usage` | Total usage for the last fully completed day (gallons); also exposes a generic `daily_history` attribute (see below) |

Additionally, a `moamwater:usage` **external statistic** is populated with
daily usage (gallons, cumulative sum) on every coordinator refresh — add it
as a **Water** source on the Home Assistant **Energy dashboard** to get the
same historical usage graphing (with previous-period navigation) as any
native water meter integration.

---

## Known data quirks: AMI meter lag

Missouri American Water's AMI meter reads are **not real-time** and are
polled by the utility's backend on an irregular cadence (not strictly once
per calendar day), with the portal's own disclaimer stating usage "may be
delayed up to 72 hours." In practice this means:

- `sensor.today_s_water_usage` and `sensor.last_hour_water_usage` can show
  data that is actually 1-3 days old, mislabeled as "today"/"this hour" —
  this is **not a bug in this integration**, it reflects exactly what the
  MyWater portal itself shows for the same period. Don't use these two
  sensors for real-time leak detection; use a dedicated flow-based device
  (e.g. Flo/Moen, StreamLabs) for that instead.
- Once a day's read does land, that **day's total is accurate** — MyWater's
  daily-chart values line up with real per-day usage (e.g. a day with heavy
  irrigation shows a correctly large total), it's only the *display
  timing/labeling* that lags, not the eventual per-day accuracy. This is why
  `moamwater:usage`'s daily statistics are trustworthy for billing/ROI
  tracking even though the "today" sensor is not trustworthy for real-time
  monitoring.
- `sensor.yesterday_s_water_usage` is generally the most reliable of the
  three real-time sensors since "yesterday" has had more time to catch up.

## Options: home vs. outside-the-home usage breakdown

MyWater's meter sits at the property line, so `moamwater:usage` reflects
**total property usage** — everything drawn through that meter, whether it's
the house itself, an irrigation system, a pool fill line, a detached shop,
outdoor spigots, etc. Irrigation is just one common example of usage that
happens outside the main line into the home; this feature works the same
way regardless of what's actually on the "outside" side of your plumbing.

If you separately have a **home-only** water usage sensor from another
integration (e.g. a Flo/Moen leak-detection valve installed on the main line
into the house, which typically excludes outdoor branches like irrigation),
you can tell this integration about it and it will derive a per-day
**outside-the-home** estimate automatically:

1. Settings → Devices & Services → **MyWater** → **Configure**
2. Select your home-only usage sensor in **"Home usage entity"**
3. Submit — the entry reloads and starts computing:
   `irrigation_estimate(day) = max(0, moamwater_daily_total(day) - home_daily_total(day))`,
   clamped at 0 since MyWater's whole-property total should always be >= a
   home-only sensor's total (small negative gaps are just meter-read
   rounding/timing, not real outside-the-home usage).

This is published as a second external statistic, `moamwater:irrigation_estimate`
(gallons, cumulative sum), so it can be charted alongside your home-only
sensor's own native statistics (e.g. in a `statistics-graph` Lovelace card)
to break total property usage out into **Home** vs. **Everything else**
(irrigation, outbuildings, pools, etc.) series. This option is entirely
optional — leave it unset if you don't have a home-only usage sensor, and no
breakout estimate will be computed. MyWater's whole-property total
(`moamwater:usage`) is always populated regardless of whether this option is
configured.

## Options: billing-cycle-to-date usage in your own config

This integration deliberately makes **no assumptions about your billing
cycle** (residential billing cycles vary by customer/account). Instead,
`sensor.yesterday_s_water_usage` exposes a generic `daily_history` attribute:
a list of `{"date": "YYYY-MM-DD", "gallons": <float>}` entries (oldest
first, typically 30-90 days of coverage). Sum whichever days you need in
your own `configuration.yaml` template, e.g. for a "30th-to-30th" cycle:

```yaml
template:
  - sensor:
      - name: "Water Cycle Confirmed Gallons"
        unit_of_measurement: "gal"
        state: >
          {% set cycle_day = 30 %}
          {% set today = now() %}
          {% if today.day >= cycle_day %}
            {% set cycle_start = today.replace(day=cycle_day, hour=0, minute=0, second=0, microsecond=0) %}
          {% else %}
            {% set first_of_month = today.replace(day=1) %}
            {% set prev_month_last = first_of_month - timedelta(days=1) %}
            {% set prev_cycle_day = [cycle_day, prev_month_last.day] | min %}
            {% set cycle_start = prev_month_last.replace(day=prev_cycle_day, hour=0, minute=0, second=0, microsecond=0) %}
          {% endif %}
          {% set history = state_attr('sensor.yesterday_s_water_usage', 'daily_history') or [] %}
          {{ history | selectattr('date', 'ge', cycle_start.strftime('%Y-%m-%d')) | map(attribute='gallons') | sum | round(1) }}
```

This keeps all cycle-specific logic in your own config, not in the shared
integration -- combine it with another home-only usage sensor's own
`utility_meter` cycle total (e.g. `max(confirmed, home_only_live)`) to build
a hybrid "live estimate now, replaced by confirmed data once it catches up"
tracker, same pattern used for the irrigation estimate above.

---

## Repository layout

```
moamwater-hacs/
  custom_components/
    moamwater/
      __init__.py        # Entry setup, login, statistics push
      api.py              # /api/mso/data client (usage + account discovery)
      auth.py              # Okta IDX login flow (identify/challenge/answer + PKCE)
      config_flow.py       # Config flow (credentials + MFA, reauth) and options flow
      const.py             # Endpoint URLs, microApplicationId map, config keys
      coordinator.py       # DataUpdateCoordinator polling hourly/daily usage
      manifest.json
      sensor.py            # Today/last-hour/yesterday usage sensors
      statistics.py         # Pushes daily usage into HA long-term statistics
      brand/                # Local brand icon/logo (HA 2026.3+ local brands)
      translations/en.json
  hacs.json
  LICENSE
  .github/workflows/{hassfest,validate}.yml
```

---

## Disclaimer

This project reverse-engineers a private, undocumented web API by observing
your own browser's authenticated network traffic. American Water may change
this API at any time without notice, which could break this integration.
No warranty is provided; you are responsible for complying with Missouri
American Water's Terms of Service when using this integration. This project
is provided for personal, educational use in automating access to *your
own* account data.
