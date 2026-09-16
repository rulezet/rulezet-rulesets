rule Trojan_BAT_AgentTesla_EC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c } 		$a_81_1 = {47 65 74 54 79 70 65 } 		$a_81_2 = {47 65 74 44 6f 6d 61 69 6e } 		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}