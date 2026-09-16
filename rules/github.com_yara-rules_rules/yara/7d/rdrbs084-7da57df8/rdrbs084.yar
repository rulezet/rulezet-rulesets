rule rdrbs084 {
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ed30327b255816bdd7590bf891aa0020"
	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
	condition:
		all of them
}