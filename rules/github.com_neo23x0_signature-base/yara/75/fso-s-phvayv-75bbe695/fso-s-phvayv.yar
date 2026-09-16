rule FSO_s_phvayv {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "205ecda66c443083403efb1e5c7f7878"
		id = "07e027a6-01a5-5250-a35e-fbfef1449cfe"
	strings:
		$s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
	condition:
		all of them
}