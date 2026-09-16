rule Trojan_Win32_SusWebSessionCookie_MK_2{
	meta:
		description = "Trojan:Win32/SusWebSessionCookie.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } 		$a_80_1 = {20 3e 4e 55 4c } 		$a_80_2 = {26 20 65 78 69 74 } 		$a_80_3 = {26 20 63 6f 70 79 } 		$a_80_4 = {5c 55 73 65 72 20 44 61 74 61 5c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}