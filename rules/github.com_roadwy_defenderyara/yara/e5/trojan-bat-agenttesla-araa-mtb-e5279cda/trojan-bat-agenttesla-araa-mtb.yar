rule Trojan_BAT_AgentTesla_ARAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 04 5d 13 08 11 07 11 05 5d 13 09 11 07 17 58 11 04 5d 13 0a 07 11 08 91 08 11 09 91 61 20 00 01 00 00 13 0b 07 11 0a 91 59 11 0b 58 11 0b 5d 13 0c 07 11 08 11 0c d2 9c 11 07 17 58 13 07 11 07 11 04 09 17 58 5a 32 b5 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}