rule Trojan_BAT_AgentTesla_MCH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 61 73 74 61 6e 65 50 72 6f 6a 65 45 4e 53 4f 4e 68 61 6c 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } 		$a_01_1 = {48 61 73 74 61 6e 65 50 72 6f 6a 65 45 4e 53 4f 4e 68 61 6c 69 } 		$a_01_2 = {53 00 65 00 63 00 72 00 65 00 74 00 61 00 72 00 79 00 20 00 49 00 6e 00 66 00 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}