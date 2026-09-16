rule RAT_Vertex
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Vertex RAT"
		reference = "http://malwareconfig.com/stats/Vertex"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "f6f5967e-6b88-5d95-8fe1-a286ee8ce64c"
	strings:
		$string1 = "DEFPATH"
		$string2 = "HKNAME"
		$string3 = "HPORT"
		$string4 = "INSTALL"
		$string5 = "IPATH"
		$string6 = "MUTEX"
		$res1 = "PANELPATH"
		$res2 = "ROOTURL"

	condition:
		all of them
}