rule Trojan_AndroidOS_SpyAgent_L{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 6e 74 65 72 5f 6f 6e 45 6e 74 65 72 } 		$a_01_1 = {4f 6e 45 78 69 74 5f 63 74 78 41 72 72 79 } 		$a_01_2 = {74 6a 66 2e 72 78 69 77 2e 67 73 77 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}