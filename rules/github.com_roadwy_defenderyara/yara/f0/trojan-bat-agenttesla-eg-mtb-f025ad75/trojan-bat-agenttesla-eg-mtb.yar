rule Trojan_BAT_AgentTesla_EG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 09 38 } 		$a_00_1 = {11 07 11 01 02 11 01 91 11 09 61 d2 9c } 		$a_00_2 = {9e 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13 08 11 06 06 02 06 91 11 08 61 d2 9c 06 17 58 0a 06 02 8e 69 } 		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*10+(#a_81_3  & 1)*1) >=11
 
}