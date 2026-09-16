rule RAT_DarkRAT
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects DarkRAT"
		reference = "http://malwareconfig.com/stats/DarkRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "8283236a-6ed1-5213-8386-a029867b9677"
	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}