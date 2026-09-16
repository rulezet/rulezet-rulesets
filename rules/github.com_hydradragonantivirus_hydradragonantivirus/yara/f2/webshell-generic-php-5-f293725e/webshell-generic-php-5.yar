rule WebShell_Generic_PHP_5 {
	meta:
		description = "PHP Webshells Github Archive - from files ex0shell.php, megabor.php, GRP WebShell 2.0 release build 2018 (C)2006,Great.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "64461ad8d8f23ea078201a31d747157f701a4e00"
		hash1 = "3df1afbcfa718da6fc8af27554834ff6d1a86562"
		hash2 = "ad86ef7f24f75081318146edc788e5466722a629"
	strings:
		$s0 = "(($perms & 0x0400) ? 'S' : '-'));" fullword
		$s10 = "} elseif (($perms & 0x8000) == 0x8000) {" fullword
		$s11 = "if (($perms & 0xC000) == 0xC000) {" fullword
		$s12 = "$info .= (($perms & 0x0008) ?" fullword
		$s16 = "// Block special" fullword
		$s18 = "$info = 's';" fullword
	condition:
		all of them
}