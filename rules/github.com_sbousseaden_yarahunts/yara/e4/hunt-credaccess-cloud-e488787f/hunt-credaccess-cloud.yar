rule hunt_credaccess_cloud {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" xor
 $gcloud1 = "\\gcloud\\credentials.db" xor
 $gcloud2 = "\\gcloud\\legacy_credentials" xor
 $gcloud3 = "\\gcloud\\access_tokens.db" xor
 $azure1 = "\\.azure\\accessTokens.json" xor
 $azure2 = "\\.azure\\azureProfile.json" xor
 $git = "\\.config\\git\\credentials" xor  $slack1 = "\\Slack\\Cookies" xor  $slack2 = "\\Slack\\StaleCookies-8" xor condition: 4 of them
}