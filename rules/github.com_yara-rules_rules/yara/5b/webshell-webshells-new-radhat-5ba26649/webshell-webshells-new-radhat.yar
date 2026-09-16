rule webshell_webshells_new_radhat {
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"
	condition:
		all of them
}