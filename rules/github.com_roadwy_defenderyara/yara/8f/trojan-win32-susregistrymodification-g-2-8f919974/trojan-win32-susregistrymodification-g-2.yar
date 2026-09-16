rule Trojan_Win32_SusRegistryModification_G_2{
	meta:
		description = "Trojan:Win32/SusRegistryModification.G,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } 		$a_80_1 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } 		$a_80_2 = {2f 76 20 4c 6f 63 61 6c 41 63 63 6f 75 6e 74 54 6f 6b 65 6e 46 69 6c 74 65 72 50 6f 6c 69 63 79 } 		$a_00_3 = {2f 00 64 00 } 		$a_80_4 = {2f 74 20 52 45 47 5f 44 57 4f 52 44 } 		$a_00_5 = {20 00 2f 00 66 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}