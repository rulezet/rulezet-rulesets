rule HYTop_DevPack_server {
	meta:
		description = "Webshells Auto-generated - file server.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d38526a215df13c7373da4635541b43"
	strings:
		$s0 = "<!-- PageServer Below -->"
	condition:
		all of them
}