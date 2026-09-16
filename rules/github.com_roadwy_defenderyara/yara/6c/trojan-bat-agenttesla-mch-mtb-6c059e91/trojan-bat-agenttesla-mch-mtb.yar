rule Trojan_BAT_AgentTesla_MCH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 11 08 19 63 61 61 13 08 16 13 13 } 		$a_01_1 = {68 00 75 00 6e 00 74 00 65 00 72 00 32 00 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}