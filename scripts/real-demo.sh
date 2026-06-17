#!/bin/bash

export FM_BASE_URL="https://wtp95711.dev.apps.dynatracelabs.com/platform/feature-management/v0.1"
export FM_TOKEN_URL="https://dev.token.dynatracelabs.com:443/sso/oauth2/token"
export FM_CLIENT_ID="$DT_CID"
export FM_CLIENT_SECRET="$DT_CS"
export FM_TENANT=wtp95711
export FM_PROJECT=jamie
export FM_STAGE=production

./demo.sh