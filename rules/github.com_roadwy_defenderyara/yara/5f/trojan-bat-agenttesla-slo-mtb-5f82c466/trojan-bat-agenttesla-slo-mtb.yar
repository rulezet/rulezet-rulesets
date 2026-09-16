rule Trojan_BAT_AgentTesla_SLO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 6f 75 01 00 0a 02 8e 69 09 da 28 b6 00 00 0a 13 05 03 02 09 11 05 07 16 6f 76 01 00 0a 13 06 08 07 16 11 06 6f 77 01 00 0a 00 09 11 05 d6 0d 00 09 02 8e 69 fe 04 13 07 11 07 2d c3 } 		$a_81_1 = {48 61 67 68 61 7a 69 6e 65 74 61 6b 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}