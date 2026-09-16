rule byshell063_ntboot_2 {
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
	condition:
		all of them
}