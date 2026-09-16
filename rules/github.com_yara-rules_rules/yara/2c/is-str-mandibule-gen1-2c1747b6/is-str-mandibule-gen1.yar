rule is__str_mandibule_gen1 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$str01 = "shared arguments too big" fullword nocase wide ascii
		$str02 = "self inject pid: %" fullword nocase wide ascii
		$str03 = "injected shellcode at 0x%lx" fullword nocase wide ascii        	
		$str04 = "target pid: %d" fullword nocase wide ascii        	
		$str05 = "mapping '%s' into memory at 0x%lx" fullword nocase wide ascii
		$str06 = "shellcode injection addr: 0x%lx" fullword nocase wide ascii
		$str07 = "loading elf at: 0x%llx" fullword nocase wide ascii
	condition:
                4 of them
}