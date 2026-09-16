rule Trojan_Win32_OffLoader_PGOF_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 66 72 61 6d 65 73 74 6f 76 65 2e 69 6e 66 6f 2f 61 6a 74 6f 2e 70 68 70 3f } 		$a_80_1 = {68 74 74 70 3a 2f 2f 6a 6f 69 6e 66 61 6c 6c 2e 78 79 7a 2f 61 6a 74 6f 73 2e 70 68 70 3f } 		$a_80_2 = {2f 73 69 6c 65 6e 74 } 		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}