rule Trojan_BAT_AgentTesla_MBCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d9 } 		$a_01_1 = {62 00 62 00 63 00 61 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}