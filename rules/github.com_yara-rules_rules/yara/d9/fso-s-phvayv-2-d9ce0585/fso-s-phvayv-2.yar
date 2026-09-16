rule FSO_s_phvayv_2 {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "205ecda66c443083403efb1e5c7f7878"
	strings:
		$s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
	condition:
		all of them
}