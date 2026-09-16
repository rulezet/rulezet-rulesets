rule Trojan_AndroidOS_SpyAgent_K{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 76 70 74 2e 63 6f 6d 3a 38 31 } 		$a_01_1 = {71 75 65 6e 65 5f 65 78 65 63 74 6f 72 5f 63 6f 76 65 72 } 		$a_01_2 = {59 69 44 75 4c 69 73 74 41 63 74 69 76 69 74 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}