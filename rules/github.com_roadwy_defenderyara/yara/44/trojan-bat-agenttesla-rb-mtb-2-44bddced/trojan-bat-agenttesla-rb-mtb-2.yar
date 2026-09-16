rule Trojan_BAT_AgentTesla_RB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 17 da 06 1e d8 b4 9c 1e 13 0a 38 ?? ?? ?? ?? 11 05 1e fe 02 13 07 11 07 2c 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}