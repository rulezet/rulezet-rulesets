rule FSO_s_reader {
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
	strings:
		$s2 = "mailto:mailbomb@hotmail."
	condition:
		all of them
}