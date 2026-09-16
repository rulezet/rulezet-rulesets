rule Trojan_BAT_AgentTesla_RS_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 11 04 28 8c 00 00 06 28 8a 00 00 06 00 28 89 00 00 06 28 8b 00 00 06 28 88 00 00 06 00 07 17 8d 58 00 00 01 25 16 28 87 00 00 06 d2 9c 6f 59 00 00 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}