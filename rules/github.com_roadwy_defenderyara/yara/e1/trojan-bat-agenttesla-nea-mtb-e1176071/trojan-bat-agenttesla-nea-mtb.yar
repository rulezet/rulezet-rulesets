rule Trojan_BAT_AgentTesla_NEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 29 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 08 11 04 11 07 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 08 11 08 2d cc 07 17 58 0b } 		$a_03_1 = {16 0c 2b 23 11 05 07 08 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 11 04 07 11 07 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 17 fe 04 13 08 11 08 2d d3 09 17 58 0d 07 17 58 0b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}