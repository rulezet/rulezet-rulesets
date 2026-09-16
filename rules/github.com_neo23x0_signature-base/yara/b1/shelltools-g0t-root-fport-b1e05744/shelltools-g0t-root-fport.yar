rule shelltools_g0t_root_Fport {
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
		id = "664e7b19-4d0b-5062-97d2-0eb34869024d"
	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."
	condition:
		all of them
}