rule multiple_webshells_0023 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "$sqlquicklaunch[] = array(\""
		$s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
	condition:
		all of them
}