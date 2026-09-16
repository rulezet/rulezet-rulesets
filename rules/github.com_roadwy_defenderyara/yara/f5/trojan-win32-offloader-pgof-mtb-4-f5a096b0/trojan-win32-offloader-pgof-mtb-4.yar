rule Trojan_Win32_OffLoader_PGOF_MTB_4{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 70 6f 72 74 65 72 2e 69 6e 66 6f 2f 6e 69 65 63 2e 70 68 70 3f } 		$a_80_1 = {68 74 74 70 3a 2f 2f 68 6f 6e 65 79 73 68 69 72 74 2e 78 79 7a 2f 6e 69 65 63 73 2e 70 68 70 3f } 		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } 		$a_80_3 = {2f 73 69 6c 65 6e 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}