rule xssshell {
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
		id = "ef89653c-5814-525a-b04e-4326a80f780c"
	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
	condition:
		all of them
}