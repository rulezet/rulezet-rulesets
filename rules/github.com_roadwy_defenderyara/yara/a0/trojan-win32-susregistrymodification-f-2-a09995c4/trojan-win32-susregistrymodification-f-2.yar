rule Trojan_Win32_SusRegistryModification_F_2{
	meta:
		description = "Trojan:Win32/SusRegistryModification.F,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } 		$a_80_1 = {48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 63 75 72 69 74 79 50 72 6f 76 69 64 65 72 73 5c 57 44 69 67 65 73 74 } 		$a_80_2 = {2f 76 20 55 73 65 4c 6f 67 6f 6e 43 72 65 64 65 6e 74 69 61 6c } 		$a_00_3 = {2f 00 64 00 } 		$a_80_4 = {2f 74 20 52 45 47 5f 44 57 4f 52 44 } 		$a_00_5 = {20 00 2f 00 66 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}