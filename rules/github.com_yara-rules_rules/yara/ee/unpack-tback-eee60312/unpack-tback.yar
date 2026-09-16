rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a9d1007823bf96fb163ab38726b48464"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}