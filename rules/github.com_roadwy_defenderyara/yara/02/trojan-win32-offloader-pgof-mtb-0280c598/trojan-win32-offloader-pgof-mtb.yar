rule Trojan_Win32_OffLoader_PGOF_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 6f 6f 66 63 61 6b 65 73 2e 69 6e 66 6f 2f 6d 61 72 6b 2e 70 68 70 } 		$a_80_1 = {76 65 73 74 73 68 65 65 74 2e 78 79 7a 2f 6d 61 72 6b 73 2e 70 68 70 } 		$a_80_2 = {2f 73 69 6c 65 6e 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}