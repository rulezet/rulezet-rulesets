rule Trojan_BAT_AgentTesla_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 1a 58 0a 00 11 07 17 58 13 07 11 07 07 fe 04 13 09 11 09 2d c7 00 11 06 17 58 13 06 11 06 07 fe 04 13 0a 11 0a 2d af } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}