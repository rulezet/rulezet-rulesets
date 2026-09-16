rule Trojan_BAT_AgentTesla_NAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 17 d6 13 05 00 11 05 09 8e 69 fe 04 13 0a 11 0a 2d d4 } 		$a_01_1 = {50 69 63 69 6d 69 7a 65 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}