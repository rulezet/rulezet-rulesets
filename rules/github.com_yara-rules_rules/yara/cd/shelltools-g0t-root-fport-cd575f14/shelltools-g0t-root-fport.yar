rule shelltools_g0t_root_Fport {
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."
	condition:
		all of them
}