rule RAT_Arcom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Arcom RAT"
		reference = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "a0598340-c4a5-53f0-a810-63e37ec669a5"
	strings:
		$a1 = "CVu3388fnek3W(3ij3fkp0930di"
		$a2 = "ZINGAWI2"
		$a3 = "clWebLightGoldenrodYellow"
		$a4 = "Ancestor for '%s' not found" wide
		$a5 = "Control-C hit" wide
		$a6 = {A3 24 25 21}

	condition:
		all of them
}