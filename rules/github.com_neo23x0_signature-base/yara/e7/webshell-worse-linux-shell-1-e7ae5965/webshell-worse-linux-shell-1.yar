rule webshell_Worse_Linux_Shell_1 {
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		old_rule_name = "webshell_Worse_Linux_Shell"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
	condition:
		all of them
}