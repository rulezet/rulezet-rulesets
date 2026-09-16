rule Trojan_BAT_AgentTesla_SG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 17 58 07 8e 69 5d 91 13 06 09 06 09 8e 69 5d 91 13 07 07 06 07 06 91 11 07 61 11 06 59 20 00 01 00 00 58 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d c9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}