rule Trojan_Win32_SusRegCredsHKLM_MK_2{
	meta:
		description = "Trojan:Win32/SusRegCredsHKLM.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } 		$a_80_1 = {20 3e 4e 55 4c } 		$a_80_2 = {26 20 65 78 69 74 } 		$a_80_3 = {72 65 67 2e 65 78 65 20 71 75 65 72 79 20 48 4b 4c 4d 20 2f 66 20 70 61 73 73 77 6f 72 64 } 		$a_80_4 = {2f 74 20 52 45 47 5f 53 5a 20 2f 73 20 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}