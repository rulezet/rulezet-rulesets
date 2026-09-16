rule Trojan_Win32_SusDLLSearchOrderl_MK_2{
	meta:
		description = "Trojan:Win32/SusDLLSearchOrderl.MK,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } 		$a_80_1 = {20 3e 4e 55 4c } 		$a_80_2 = {26 20 65 78 69 74 } 		$a_80_3 = {72 75 6e 64 6c 6c 33 32 } 		$a_80_4 = {70 68 6f 6e 65 68 6f 6d 65 5f 6d 61 69 6e 20 } 		$a_80_5 = {70 68 6f 6e 65 48 6f 6d 65 } 		$a_80_6 = {5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}