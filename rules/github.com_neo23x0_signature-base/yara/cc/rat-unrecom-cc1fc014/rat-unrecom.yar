rule RAT_unrecom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects unrecom RAT"
		reference = "http://malwareconfig.com/stats/unrecom"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "56b11c22-f43c-5192-9a0a-0ac14b0cd041"
	strings:
		$meta = "META-INF"
		$conf = "load/ID"
		$a = "load/JarMain.class"
		$b = "load/MANIFEST.MF"
		$c = "plugins/UnrecomServer.class"

	condition:
		all of them
}