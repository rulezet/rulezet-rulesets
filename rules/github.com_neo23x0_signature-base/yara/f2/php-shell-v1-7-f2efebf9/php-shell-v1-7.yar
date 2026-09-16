rule PHP_Shell_v1_7 {
	meta:
		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b5978501c7112584532b4ca6fb77cba5"
		id = "7eb69ac3-90bb-5a44-8dcd-e71f5edcf18f"
	strings:
		$s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
	condition:
		all of them
}