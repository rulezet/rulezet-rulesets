rule Trojan_Win32_SusDarkCrystal_A{
	meta:
		description = "Trojan:Win32/SusDarkCrystal.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 } 		$a_80_1 = {47 65 74 2d 52 61 6e 64 6f 6d 20 } 		$a_80_2 = {2d 4d 69 6e 69 6d 75 6d 20 } 		$a_80_3 = {2d 4d 61 78 69 6d 75 6d } 		$a_80_4 = {53 74 61 72 74 2d 53 6c 65 65 70 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}