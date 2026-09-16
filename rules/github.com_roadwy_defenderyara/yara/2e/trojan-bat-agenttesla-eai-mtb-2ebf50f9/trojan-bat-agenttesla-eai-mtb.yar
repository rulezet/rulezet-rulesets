rule Trojan_BAT_AgentTesla_EAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 25 9d 6f ?? 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 0d 2b 11 08 09 07 09 9a 1f 10 28 ?? 00 00 0a 9c 09 17 58 0d 09 07 8e 69 32 e9 } 		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } 		$a_01_2 = {53 70 6c 69 74 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}