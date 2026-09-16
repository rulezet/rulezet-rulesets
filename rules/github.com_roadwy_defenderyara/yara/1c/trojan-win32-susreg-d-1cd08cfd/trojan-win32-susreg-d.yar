rule Trojan_Win32_SusReg_D{
	meta:
		description = "Trojan:Win32/SusReg.D,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f } 		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 74 65 6d 70 2e 69 6e 69 } 		$a_80_2 = {74 61 73 6b 6c 69 73 74 } 		$a_80_3 = {6d 61 6b 65 63 61 62 } 		$a_80_4 = {74 65 6d 70 2e 63 61 62 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}