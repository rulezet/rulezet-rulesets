rule Trojan_AndroidOS_SpyAgent_U{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.U,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 65 73 68 69 20 65 6e 74 65 72 20 6d 61 69 6e 32 32 32 } 		$a_01_1 = {63 65 73 68 69 20 65 6e 74 65 72 20 68 6f 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}