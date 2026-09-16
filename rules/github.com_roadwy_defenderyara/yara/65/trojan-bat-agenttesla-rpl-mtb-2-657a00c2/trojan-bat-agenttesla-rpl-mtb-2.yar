rule Trojan_BAT_AgentTesla_RPL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 17 13 07 16 13 08 2b 10 11 07 20 00 01 00 00 5a 13 07 11 08 17 58 13 08 11 08 11 06 fe 04 13 0b 11 0b 2d e4 11 05 11 07 07 11 06 91 5a 58 13 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}