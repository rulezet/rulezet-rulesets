rule Trojan_BAT_AgentTesla_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 11 04 07 11 04 18 5a 18 6f 76 00 00 0a 1f 10 28 77 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4 d0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}