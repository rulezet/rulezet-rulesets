rule Trojan_BAT_AgentTesla_RVKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RVKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 1f b6 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 e0 00 00 00 17 00 00 00 59 00 00 00 cf 00 00 00 c9 00 00 00 01 00 00 00 83 01 00 00 02 00 00 00 38 01 00 00 4a 00 00 00 01 00 00 00 04 00 00 00 09 00 00 00 22 00 00 00 37 00 00 00 0d 00 00 00 01 00 00 00 0a 00 00 00 07 00 00 00 07 00 00 00 06 } 		$a_81_1 = {6b 75 72 73 61 63 68 46 6f 72 41 78 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}