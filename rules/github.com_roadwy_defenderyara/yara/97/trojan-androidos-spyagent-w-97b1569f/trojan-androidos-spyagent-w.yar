rule Trojan_AndroidOS_SpyAgent_W{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 56 69 64 65 6f 20 5c 64 } 		$a_01_1 = {2d 2d 20 20 46 72 6f 6e 74 20 43 61 6d 65 72 61 } 		$a_01_2 = {74 61 6b 65 70 69 63 20 5c 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}