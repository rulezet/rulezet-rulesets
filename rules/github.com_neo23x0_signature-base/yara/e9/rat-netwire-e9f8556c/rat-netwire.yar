rule RAT_NetWire
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> & David Cannings"
		date = "01.04.2014"
		description = "Detects NetWire RAT"
		reference = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "f0077e8c-3e6a-5a98-9171-b0d81f24d27a"
	strings:
		$exe1 = "%.2d-%.2d-%.4d"
		$exe2 = "%s%.2d-%.2d-%.4d"
		$exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$exe4 = "wcnwClass"
		$exe5 = "[Ctrl+%c]"
		$exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
		$exe7 = "%s\\.purple\\accounts.xml"

	condition:
		all of them
}