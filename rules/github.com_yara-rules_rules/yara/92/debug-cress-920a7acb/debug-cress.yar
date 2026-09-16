rule Debug_cress {
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "36a416186fe010574c9be68002a7286a"
	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"
	condition:
		all of them
}