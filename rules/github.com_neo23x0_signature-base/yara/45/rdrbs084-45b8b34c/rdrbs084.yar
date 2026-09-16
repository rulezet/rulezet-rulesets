rule rdrbs084 {
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ed30327b255816bdd7590bf891aa0020"
		id = "97548273-6894-5c9f-8cca-d966ce770ada"
	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
	condition:
		all of them
}