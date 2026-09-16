rule Trojan_BAT_AgentTesla_RPY_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 1a 11 07 5a 09 19 1a 11 07 5a 58 91 9c 11 04 17 1a 11 07 5a 58 09 18 1a 11 07 5a 58 91 9c 11 04 18 1a 11 07 5a 58 09 17 1a 11 07 5a 58 91 9c 11 04 19 1a 11 07 5a 58 09 1a 11 07 5a 91 9c 00 11 07 17 58 13 07 11 07 1f 10 fe 04 13 08 11 08 2d ac } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}