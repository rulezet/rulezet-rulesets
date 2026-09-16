rule Trojan_AndroidOS_SpyAgent_K_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 49 73 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e 47 72 61 6e 74 } 		$a_01_1 = {55 6e 69 46 65 53 65 72 76 69 63 65 } 		$a_01_2 = {53 4d 53 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 50 55 53 48 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}