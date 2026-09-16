rule Trojan_BAT_AgentTesla_EAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 06 07 91 17 62 06 07 91 1d 63 60 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e1 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}