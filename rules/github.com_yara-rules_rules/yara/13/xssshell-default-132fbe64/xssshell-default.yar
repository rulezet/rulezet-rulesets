rule xssshell_default {
	meta:
		description = "Webshells Auto-generated - file default.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
	condition:
		all of them
}