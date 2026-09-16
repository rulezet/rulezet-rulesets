rule Trojan_BAT_AgentTesla_SC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 61 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 08 07 11 07 11 08 9c 11 05 07 11 07 91 6f 59 00 00 0a 11 04 17 58 13 04 11 04 09 08 17 58 5a 32 a8 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}