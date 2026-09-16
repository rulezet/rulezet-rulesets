rule FSO_s_zehir4_2 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"
	condition:
		all of them
}