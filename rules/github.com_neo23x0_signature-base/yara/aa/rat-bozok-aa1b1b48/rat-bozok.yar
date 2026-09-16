rule RAT_Bozok
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bozok RAT"
		reference = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "b1d22e8c-39aa-52e7-9ca8-2b35bb82f7de"
	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase

	condition:
		all of them
}