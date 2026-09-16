rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a9d1007823bf96fb163ab38726b48464"
		id = "b5f93621-e1e9-5aed-b574-471b4c1f9570"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}