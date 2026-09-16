rule xssshell {
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
	condition:
		all of them
}