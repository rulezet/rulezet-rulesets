rule RAT_LuxNet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects LuxNet RAT"
		reference = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "277db509-5ba0-5d1b-b17a-d5914f1f1650"
	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}