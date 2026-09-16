rule webshell_asp_404 {
	meta:
		description = "Web Shell - file 404.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"
	strings:
		$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
	condition:
		all of them
}