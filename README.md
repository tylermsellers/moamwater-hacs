# Missouri American Water (MyWater) — Home Assistant Integration

[![HACS Custom Repository](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Home Assistant integration for **Missouri American Water**'s MyWater customer
portal (`mywaterv2.amwater.com`), pulling hourly and daily water usage
(gallons) into Home Assistant — including long-term statistics compatible
with the **Energy dashboard**'s water source, the same way the community
Spire gas integration works.

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
| `sensor.yesterday_s_water_usage` | Total usage for the last fully completed day (gallons) |

Additionally, a `moamwater:usage` **external statistic** is populated with
daily usage (gallons, cumulative sum) on every coordinator refresh — add it
as a **Water** source on the Home Assistant **Energy dashboard** to get the
same historical usage graphing (with previous-period navigation) as any
native water meter integration.

---

## Repository layout

```
moamwater-hacs/
  custom_components/
    moamwater/
      __init__.py        # Entry setup, login, statistics push
      api.py              # /api/mso/data client (usage + account discovery)
      auth.py              # Okta IDX login flow (identify/challenge/answer + PKCE)
      config_flow.py       # Two-step config flow (credentials, then MFA)
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
