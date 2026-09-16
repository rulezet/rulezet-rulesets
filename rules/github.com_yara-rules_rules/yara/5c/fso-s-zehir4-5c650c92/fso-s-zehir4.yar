rule FSO_s_zehir4 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s5 = " byMesaj "
	condition:
		all of them
}