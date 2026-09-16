rule TrojanSpy_AndroidOS_SpyAgent_L{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6b 61 6d 72 61 6e 2e 68 75 6e 7a 61 6e 65 77 73 } 		$a_01_1 = {63 68 65 63 6b 69 6e 67 53 65 73 73 69 6f 6e 4d 61 6e 67 65 72 46 6f 72 55 70 6c 6f 61 64 69 6e 67 } 		$a_01_2 = {66 65 74 63 68 49 73 4d 65 73 73 61 67 65 73 41 64 64 65 64 } 		$a_01_3 = {66 65 74 63 68 49 73 43 6f 6e 74 61 63 74 73 41 64 64 65 64 } 		$a_01_4 = {73 61 76 65 41 70 70 73 41 64 64 65 64 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}