rule Trojan_BAT_AgentTesla_RPX_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 16 13 06 2b 5c 00 16 13 07 2b 44 00 16 13 08 2b 2c 00 09 11 04 11 07 58 11 06 11 08 58 } 		$a_01_1 = {13 0a 08 07 11 0a 9c 07 17 58 0b 11 08 17 58 13 08 00 11 08 17 fe 04 13 0b 11 0b 2d c9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}