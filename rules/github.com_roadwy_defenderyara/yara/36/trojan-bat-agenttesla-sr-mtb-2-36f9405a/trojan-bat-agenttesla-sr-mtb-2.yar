rule Trojan_BAT_AgentTesla_SR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 22 11 04 5d 13 23 11 22 17 58 11 04 5d 13 24 07 11 24 91 20 00 01 00 00 58 13 25 07 11 23 91 13 26 11 26 08 11 22 1f 16 5d 91 61 13 27 11 27 11 25 59 13 28 07 11 23 11 28 20 00 01 00 00 5d d2 9c 00 11 22 17 58 13 22 11 22 11 04 09 17 58 5a fe 04 13 29 11 29 2d a6 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}