rule Trojan_BAT_AgentTesla_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 18 6f 13 00 00 0a 1f 10 28 14 00 00 0a 13 04 11 04 16 3f 08 00 00 00 08 11 04 6f 15 00 00 0a 09 18 58 0d 09 07 6f 16 00 00 0a 32 d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}