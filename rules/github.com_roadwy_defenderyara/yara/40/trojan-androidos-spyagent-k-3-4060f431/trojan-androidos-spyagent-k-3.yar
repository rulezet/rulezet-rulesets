rule Trojan_AndroidOS_SpyAgent_K_3{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6c 65 61 73 65 20 63 6f 6e 66 69 67 20 46 54 50 20 73 65 72 76 65 72 } 		$a_01_1 = {6e 6f 20 62 61 73 65 6c 6f 63 20 64 61 74 61 } 		$a_01_2 = {65 6d 61 69 6c 20 6d 73 67 20 74 79 70 65 20 65 72 72 6f 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}