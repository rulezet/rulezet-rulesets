rule WFYARAGEN_G4472_rules_1
{

	meta:

	description = "Double-var fn around base64 string"

	strings:

	$re = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*['"][A-Za-z\d\/\+]+=*['"]\s*\)/

	condition:
	$re
}