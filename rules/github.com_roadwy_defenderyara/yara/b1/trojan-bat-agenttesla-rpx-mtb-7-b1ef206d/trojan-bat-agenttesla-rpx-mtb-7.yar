rule Trojan_BAT_AgentTesla_RPX_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 08 11 04 5d 13 09 11 08 11 05 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 09 91 08 11 0a 91 61 13 0c 11 0c 07 11 0b 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0d 07 11 09 11 0d d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0e 11 0e 2d aa } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}