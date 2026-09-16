rule Trojan_BAT_AgentTesla_RPY_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 17 59 13 07 11 12 20 31 01 00 00 91 1f 68 59 13 10 38 5f fe ff ff 11 06 74 05 00 00 1b 11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 04 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 11 12 20 9c 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}