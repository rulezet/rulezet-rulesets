rule RAT_Paradox
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Paradox RAT"
		reference = "http://malwareconfig.com/stats/Paradox"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "2f1e6226-799b-54eb-a4a4-6c0f1bf561b4"
	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}