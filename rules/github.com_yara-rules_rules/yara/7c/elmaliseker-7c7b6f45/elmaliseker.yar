rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}