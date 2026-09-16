rule Trojan_BAT_AgentTesla_SKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 33 2e 37 32 2e 38 38 2e 32 32 34 2f 66 31 2f 58 6c 75 75 6d 6b 61 6d 6f 2e 6d 70 34 } 		$a_81_1 = {43 6f 6d 70 72 65 73 73 65 64 42 79 74 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}