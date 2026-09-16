rule webshell_webshells_new_xxxx {
	meta:
		description = "Web shells - generated from file xxxx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "5bcba70b2137375225d8eedcde2c0ebb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php eval($_POST[1]);?>  " fullword
	condition:
		all of them
}