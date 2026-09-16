rule Trojan_BAT_AgentTesla_SKC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 06 11 07 11 05 11 07 18 5a 18 6f 0f 00 00 0a 1f 10 28 10 00 00 0a 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 da } 		$a_00_1 = {28 11 00 00 0a 28 12 00 00 0a 8c 13 00 00 01 72 4d 00 00 70 28 13 00 00 0a 28 14 00 00 0a 13 08 16 13 09 2b 25 } 		$a_81_2 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 68 6f 72 73 65 2f 6a 73 2f 62 77 5f 62 75 6e 64 6c 65 2e 6a 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}