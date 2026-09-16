rule webshell_mumaasp_com {
	meta:
		description = "Web Shell - file mumaasp.com.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cce32b2e18f5357c85b6d20f564ebd5d"
	strings:
		$s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
	condition:
		all of them
}