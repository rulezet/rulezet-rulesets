rule RAT_CyberGate
{

	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects CyberGate RAT"
		reference = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "387e7c89-c766-54cf-aac0-3ba03092bc25"
	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}