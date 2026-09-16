rule Trojan_Win32_SusRegistryModification_D_2{
	meta:
		description = "Trojan:Win32/SusRegistryModification.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } 		$a_80_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 69 72 65 } 		$a_00_2 = {20 00 2f 00 46 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}