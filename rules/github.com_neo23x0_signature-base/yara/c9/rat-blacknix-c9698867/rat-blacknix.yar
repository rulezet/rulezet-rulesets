rule RAT_BlackNix
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlackNix RAT"
		reference = "http://malwareconfig.com/stats/BlackNix"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "d7814184-3ae4-53f1-a602-c3fbc02573c3"
	strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	condition:
		all of them
}