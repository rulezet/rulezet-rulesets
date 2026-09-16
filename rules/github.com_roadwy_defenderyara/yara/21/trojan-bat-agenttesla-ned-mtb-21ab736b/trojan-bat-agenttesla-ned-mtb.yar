rule Trojan_BAT_AgentTesla_NED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 29 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 0f 11 0f 28 ?? ?? ?? 0a 13 10 08 11 04 11 10 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 11 11 11 2d cc 07 17 58 0b 00 11 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}