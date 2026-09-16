rule Trojan_BAT_AgentTesla_RPX_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 13 08 07 09 17 58 07 8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a 07 11 06 11 0a d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 0b 11 0b 2d ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}