rule webshell_jsp_guige {
	meta:
		description = "Web Shell - file guige.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2c9f2dafa06332957127e2c713aacdd2"
	strings:
		$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
	condition:
		all of them
}