rule Trojan_BAT_AgentTesla_SLO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {08 09 a3 06 00 00 1b 13 04 11 04 16 06 07 11 04 8e 69 28 3c 00 00 0a 07 11 04 8e 69 58 0b 09 17 58 0d 09 08 8e 69 32 d8 } 		$a_81_1 = {24 65 62 65 31 39 33 66 62 2d 65 37 64 30 2d 34 61 66 34 2d 61 39 35 33 2d 34 62 66 32 36 39 38 36 31 34 37 62 } 		$a_81_2 = {56 66 75 71 7a 6f 68 6f 64 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_3 = {44 70 6a 6a 78 65 6e } 	condition:
		((#a_00_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}