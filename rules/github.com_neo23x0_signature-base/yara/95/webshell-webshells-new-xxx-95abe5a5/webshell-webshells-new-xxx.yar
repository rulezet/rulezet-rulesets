rule webshell_webshells_new_xxx {
	meta:
		description = "Web shells - generated from file xxx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
	condition:
		all of them
}