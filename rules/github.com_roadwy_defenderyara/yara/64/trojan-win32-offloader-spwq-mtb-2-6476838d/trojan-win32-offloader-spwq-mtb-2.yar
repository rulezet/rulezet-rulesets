rule Trojan_Win32_OffLoader_SPWQ_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.SPWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {62 6f 78 67 72 61 6e 64 66 61 74 68 65 72 2e 69 6e 66 6f 2f 70 6f 6c 69 2e 70 68 70 } 		$a_80_1 = {63 68 69 63 6b 65 6e 73 6c 65 76 65 6c 2e 78 79 7a 2f 70 6f 6c 69 73 2e 70 68 70 } 		$a_80_2 = {2f 73 69 6c 65 6e 74 } 	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}