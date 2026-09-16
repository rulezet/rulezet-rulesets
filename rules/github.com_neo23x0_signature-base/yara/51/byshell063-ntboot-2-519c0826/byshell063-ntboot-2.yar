rule byshell063_ntboot_2 {
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
		id = "9bcb401d-619b-54b8-be51-f0e3b6eb096c"
	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
	condition:
		all of them
}