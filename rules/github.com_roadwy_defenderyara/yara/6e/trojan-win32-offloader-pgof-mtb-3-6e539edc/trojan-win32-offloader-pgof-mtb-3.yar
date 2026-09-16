rule Trojan_Win32_OffLoader_PGOF_MTB_3{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 61 72 6d 79 74 72 65 61 74 6d 65 6e 74 2e 69 6e 66 6f 2f 79 74 72 69 2e 70 68 70 3f } 		$a_80_1 = {68 74 74 70 3a 2f 2f 61 72 6d 72 6f 75 74 65 2e 78 79 7a 2f 79 74 72 69 73 2e 70 68 70 3f } 		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } 		$a_80_3 = {2f 73 69 6c 65 6e 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}