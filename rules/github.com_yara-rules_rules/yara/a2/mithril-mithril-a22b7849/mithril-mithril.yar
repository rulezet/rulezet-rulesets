rule Mithril_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "017191562d72ab0ca551eb89256650bd"
	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"
	condition:
		all of them
}