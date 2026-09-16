rule RAT_PythoRAT
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Python RAT"
		reference = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "fc98c513-1abf-5331-b351-f6182e5b19c5"
	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}