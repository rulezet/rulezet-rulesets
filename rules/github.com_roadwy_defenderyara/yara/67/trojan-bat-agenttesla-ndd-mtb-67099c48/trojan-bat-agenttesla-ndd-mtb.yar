rule Trojan_BAT_AgentTesla_NDD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2a 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 17 13 09 08 11 08 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d cb 07 17 58 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}