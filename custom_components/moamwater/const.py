"""Constants for the Missouri American Water (MyWater) integration."""

DOMAIN = "moamwater"

# --- Okta / auth endpoints ---
OKTA_BASE_URL = "https://auth.amwater.com"
OKTA_ISSUER_PATH = "/oauth2/aus29oxmv4bzpt55X5d7"  # captured from bearer token 'iss' claim
OKTA_CLIENT_ID = "0oa29ovb79AWEoS8V5d7"  # captured from bearer token 'cid' claim

# This Okta app registration's allowed grant types are `authorization_code`,
# `password`, and `refresh_token` (confirmed via the `unauthorized_client`
# error returned by /v1/interact -- the pure Interaction Code/OIE grant is
# NOT enabled for this client). However, this org IS an Identity Engine (OIE)
# tenant whose hosted Sign-In Widget drives login via the IDX API
# (`/idp/idx/*`) using a `stateToken`/`stateHandle` obtained by first loading
# `/v1/authorize` -- confirmed via a HAR capture of a real successful login.
# This is different from both the classic AuthN API (`/api/v1/authn`, which
# this org's widget does NOT use) and the raw Interaction Code flow
# (`/v1/interact`, blocked by the grant-type restriction above).
OKTA_IDX_INTROSPECT_URL = f"{OKTA_BASE_URL}/idp/idx/introspect"
OKTA_IDX_IDENTIFY_URL = f"{OKTA_BASE_URL}/idp/idx/identify"
OKTA_IDX_CHALLENGE_URL = f"{OKTA_BASE_URL}/idp/idx/challenge"
OKTA_IDX_CHALLENGE_ANSWER_URL = f"{OKTA_BASE_URL}/idp/idx/challenge/answer"
OKTA_DEVICE_NONCE_URL = f"{OKTA_BASE_URL}/api/v1/internal/device/nonce"
OKTA_TOKEN_REDIRECT_URL = f"{OKTA_BASE_URL}/login/token/redirect"

MYWATER_BASE_URL = "https://mywaterv2.amwater.com"
MYWATER_LOGIN_REDIRECT_PATH = "/openidlogin"
MYWATER_DATA_ENDPOINT = "/api/mso/data"
MYWATER_MICROAPP_ENDPOINT = "/api/vux/microapp"

# Redirect URI the MyWater SPA registers with Okta (captured from network trace).
# Must match exactly what Okta expects for the authorization code exchange.
OKTA_REDIRECT_URI = f"{MYWATER_BASE_URL}{MYWATER_LOGIN_REDIRECT_PATH}"

# OAuth/OIDC scopes requested by the MyWater SPA (standard Okta SPA defaults).
OKTA_SCOPES = "openid email profile UserContext offline_access GroupMembership"

# --- MyWater application identifiers (from captured usage request payload) ---
SOLUTION_ID = "com::amwater::enhancedportal::enhancedportal"
SOLUTION_PAGE_ID = "com::amwater::enhancedportal::landingPage"
APPLICATION_ID = "com::amwater::enhancedportal::usageoverview"

MICRO_APP_HOURLY = "usageOverviewHourlyChart"
MICRO_APP_DAILY = "usageOverviewDailyChart"
MICRO_APP_MONTHLY_12 = "usageOverview12MonthlyChart"
MICRO_APP_MONTHLY_24 = "usageOverview24MonthlyChart"
MICRO_APP_MONTHLY_4YR = "usageOverviewMonthlyChartFourYears"

# --- Config entry keys ---
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_BUSINESS_PARTNER_NUMBER = "business_partner_number"
CONF_CONNECTION_CONTRACT_NUMBER = "connection_contract_number"
CONF_PREMISE_ID = "premise_id"
CONF_STATE_CODE = "state_code"
CONF_REFRESH_TOKEN = "refresh_token"

# --- Storage keys for tokens ---
DATA_ACCESS_TOKEN = "access_token"
DATA_ID_TOKEN = "id_token"
DATA_REFRESH_TOKEN = "refresh_token"
DATA_EXPIRES_AT = "expires_at"

# Persisted in entry.data so a restart within the token's ~10hr lifetime can
# skip login entirely instead of re-running the full interactive/SMS flow.
CONF_ACCESS_TOKEN = "access_token"
CONF_ACCESS_TOKEN_EXPIRES_AT = "access_token_expires_at"

# Filename (relative to HA's config/.storage dir) used to persist Okta's own
# session cookies (e.g. `sid`) across restarts, so that even once the access
# token itself has expired we can try a silent `/v1/authorize` replay (Okta
# SSO) before falling back to a full interactive login.
COOKIE_JAR_FILENAME_TEMPLATE = "moamwater_{entry_id}_cookies.pickle"

DEFAULT_SCAN_INTERVAL_MINUTES = 60

STATISTIC_ID = "moamwater:usage"

# Optional entry option: a home-only water usage sensor (e.g. a Flo/Moen
# leak-detector's daily usage sensor) used to derive an "irrigation-only"
# estimate (MyWater's whole-property daily total minus that day's home-only
# usage, clamped to >=0). Not required -- if unset, no irrigation estimate
# is imported.
CONF_HOME_USAGE_ENTITY_ID = "home_usage_entity_id"

STATISTIC_ID_IRRIGATION = "moamwater:irrigation_estimate"

# Optional entry option: day-of-month your MyWater billing cycle starts
# (e.g. 30 for a "30th-to-30th" cycle). When set, a "Billing Cycle Usage"
# sensor sums the daily chart's values since the most recent occurrence of
# this day, giving an always-current, self-correcting cycle-to-date total
# computed directly from the same (now-fixed) daily data used for the
# moamwater:usage external statistic -- no separate accumulator/automation
# or manual seeding required.
CONF_BILLING_CYCLE_START_DAY = "billing_cycle_start_day"
