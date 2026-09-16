rule Trojan_BAT_AgentTesla_AMCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 11 0c 08 11 06 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 09 11 0e 11 07 5d d2 9c 00 11 06 17 58 13 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}