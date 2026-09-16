rule indexer_asp {
	meta:
		description = "Semi-Auto-generated  - file indexer.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9ea82afb8c7070817d4cdf686abe0300"
		id = "84ff60f9-36f7-5d29-9f38-8088fb42582e"
	strings:
		$s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
		$s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
	condition:
		1 of them
}