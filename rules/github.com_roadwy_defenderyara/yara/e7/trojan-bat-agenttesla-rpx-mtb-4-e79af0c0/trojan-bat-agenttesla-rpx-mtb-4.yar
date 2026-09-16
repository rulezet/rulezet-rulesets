rule Trojan_BAT_AgentTesla_RPX_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 18 07 08 18 5b 02 08 18 ?? ?? 00 00 0a 1f 10 ?? ?? 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0 07 13 04 11 04 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}