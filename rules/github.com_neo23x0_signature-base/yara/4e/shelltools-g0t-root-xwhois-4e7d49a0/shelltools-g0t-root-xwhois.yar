rule shelltools_g0t_root_xwhois {
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
		id = "8f3b3bb2-5884-584a-8220-b6edbfebc8a3"
	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"
	condition:
		all of them
}