rule Trojan_BAT_AgentTesla_MBFJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 11 58 13 19 11 0d 11 12 91 13 1a 11 1a 11 13 11 08 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 11 0d 11 12 11 1c 11 11 5d d2 9c 11 08 17 58 13 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}