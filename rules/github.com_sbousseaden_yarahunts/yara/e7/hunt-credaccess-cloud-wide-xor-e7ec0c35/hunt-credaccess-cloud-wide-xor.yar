rule hunt_credaccess_cloud_wide_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide xor
 $gcloud1 = "\\gcloud\\credentials.db" wide xor
 $gcloud2 = "\\gcloud\\legacy_credentials" wide xor
 $gcloud3 = "\\gcloud\\access_tokens.db" wide xor
 $azure1 = "\\.azure\\accessTokens.json" wide xor
 $azure2 = "\\.azure\\azureProfile.json" wide xor
 $git = "\\.config\\git\\credentials" wide xor  $slack1 = "\\Slack\\Cookies" wide xor  $slack2 = "\\Slack\\StaleCookies-8" wide xor condition: 4 of them
}