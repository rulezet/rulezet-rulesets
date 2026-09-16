rule Mithril_v1_45_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."
	condition:
		all of them
}