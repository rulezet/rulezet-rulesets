rule Trojan_Win32_SusChmod777_MK_2{
	meta:
		description = "Trojan:Win32/SusChmod777.MK,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } 		$a_80_1 = {20 3e 4e 55 4c } 		$a_80_2 = {26 20 65 78 69 74 } 		$a_80_3 = {69 63 61 63 6c 73 } 		$a_80_4 = {73 62 64 2e 62 69 6e } 		$a_80_5 = {2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}