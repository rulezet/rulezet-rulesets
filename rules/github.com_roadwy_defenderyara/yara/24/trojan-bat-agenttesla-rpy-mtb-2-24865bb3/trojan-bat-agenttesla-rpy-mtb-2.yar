rule Trojan_BAT_AgentTesla_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 0d 11 05 17 58 13 05 11 05 04 3f de ff ff ff 16 13 06 38 1b 00 00 00 06 09 5a 07 58 08 5d 13 04 0e 04 11 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}