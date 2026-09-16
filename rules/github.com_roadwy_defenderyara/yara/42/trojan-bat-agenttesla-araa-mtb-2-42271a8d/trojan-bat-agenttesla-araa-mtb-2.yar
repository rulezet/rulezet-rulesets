rule Trojan_BAT_AgentTesla_ARAA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 09 11 08 17 58 13 0a 11 08 11 04 5d 13 0b 11 0a 11 04 5d 13 0c 07 11 0c 91 11 09 58 13 0d 07 11 0b 91 13 0e 11 0e 08 11 08 1f 16 5d 91 61 13 0f 11 0f 11 0d 59 13 10 07 11 0b 11 10 11 09 5d d2 9c 11 08 17 58 13 08 11 08 11 04 09 17 58 5a 32 a9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}