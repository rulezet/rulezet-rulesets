rule RAT_Infinity
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Infinity RAT"
		reference = "http://malwareconfig.com/stats/Infinity"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "b70f9459-fa84-516f-841d-d9617856eb4d"
	strings:
		$a = "CRYPTPROTECT_PROMPTSTRUCT"
		$b = "discomouse"
		$c = "GetDeepInfo"
		$d = "AES_Encrypt"
		$e = "StartUDPFlood"
		$f = "BATScripting" wide
		$g = "FBqINhRdpgnqATxJ.html" wide
		$i = "magic_key" wide

	condition:
		all of them
}