rule FSO_s_indexer {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "135fc50f85228691b401848caef3be9e"
		id = "fba053d7-5413-563f-8c27-0554349500b2"
	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
	condition:
		all of them
}