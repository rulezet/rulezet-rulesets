rule Trojan_BAT_AgentTesla_SIO_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 83 00 00 06 13 05 11 04 1f 16 5d 13 06 11 04 17 58 13 07 07 11 04 91 11 05 11 06 91 61 13 08 07 11 04 11 08 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 09 11 09 2d b5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}