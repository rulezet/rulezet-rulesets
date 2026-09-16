rule RAT_ShadowTech : FILE {
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects ShadowTech RAT"
		reference = "http://malwareconfig.com/stats/ShadowTech"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		id = "1fb15030-b400-5e70-b183-81e2527d5556"
	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}