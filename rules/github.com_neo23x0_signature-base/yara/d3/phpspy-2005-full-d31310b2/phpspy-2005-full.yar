rule phpspy_2005_full {
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d1c69bb152645438440e6c903bac16b2"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
	condition:
		all of them
}