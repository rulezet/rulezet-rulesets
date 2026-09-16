rule Trojan_Win32_SusRegistryModification_C_2{
	meta:
		description = "Trojan:Win32/SusRegistryModification.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } 		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 		$a_80_2 = {6d 69 5f 77 64 69 67 65 73 74 2e 70 73 31 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}