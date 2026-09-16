rule hunt_credaccess_cloud_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide base64
 $gcloud1 = "\\gcloud\\credentials.db" wide base64
 $gcloud2 = "\\gcloud\\legacy_credentials" wide base64
 $gcloud3 = "\\gcloud\\access_tokens.db" wide base64
 $azure1 = "\\.azure\\accessTokens.json" wide base64
 $azure2 = "\\.azure\\azureProfile.json" wide base64
 $git = "\\.config\\git\\credentials" wide base64  $slack1 = "\\Slack\\Cookies" wide base64  $slack2 = "\\Slack\\StaleCookies-8" wide base64 condition: 4 of them
}