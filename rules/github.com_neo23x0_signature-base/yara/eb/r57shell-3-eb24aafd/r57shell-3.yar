rule r57shell_3 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
		id = "4129d77c-2981-587b-a83e-8767dc3a48d8"
	strings:
		$s1 = "<b>\".$_POST['cmd']"
	condition:
		all of them
}