rule Trojan_BAT_AgentTesla_AI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 14 00 00 0a 00 16 28 15 00 00 0a 00 73 77 00 00 06 0a 2a } 		$a_01_1 = {28 e6 00 00 0a 28 81 00 00 06 28 7a 00 00 06 6f e7 00 00 0a 0a 02 06 28 78 00 00 06 0b 02 07 28 7b 00 00 06 00 16 28 e8 00 00 0a 00 16 0c 2b 00 08 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}