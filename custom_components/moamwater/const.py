"""Constants for the Missouri American Water (MyWater) integration."""

DOMAIN = "moamwater"

# --- Okta / auth endpoints ---
OKTA_BASE_URL = "https://auth.amwater.com"
OKTA_ISSUER_PATH = "/oauth2/aus29oxmv4bzpt55X5d7"  # captured from bearer token 'iss' claim
OKTA_CLIENT_ID = "0oa29ovb79AWEoS8V5d7"  # captured from bearer token 'cid' claim

MYWATER_BASE_URL = "https://mywaterv2.amwater.com"
MYWATER_LOGIN_REDIRECT_PATH = "/openidlogin"
MYWATER_DATA_ENDPOINT = "/api/mso/data"

# Redirect URI the MyWater SPA registers with Okta (captured from network trace).
# Must match exactly what Okta expects for the authorization code exchange.
OKTA_REDIRECT_URI = f"{MYWATER_BASE_URL}{MYWATER_LOGIN_REDIRECT_PATH}"

# OAuth/OIDC scopes requested by the MyWater SPA (standard Okta SPA defaults).
OKTA_SCOPES = "openid profile email offline_access"

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

# --- Storage keys for tokens ---
DATA_ACCESS_TOKEN = "access_token"
DATA_ID_TOKEN = "id_token"
DATA_REFRESH_TOKEN = "refresh_token"
DATA_EXPIRES_AT = "expires_at"

DEFAULT_SCAN_INTERVAL_MINUTES = 60

STATISTIC_ID = "moamwater:usage"
