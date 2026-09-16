rule xssshell_default {
	meta:
		description = "Webshells Auto-generated - file default.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
		id = "1c221572-4cb5-5806-a856-0f857dba230a"
	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
	condition:
		all of them
}