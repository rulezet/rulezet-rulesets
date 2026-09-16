rule Trojan_BAT_AgentTesla_EG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 02 11 04 91 07 11 04 07 8e b7 5d 91 61 09 11 04 09 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da } 		$a_81_1 = {52 65 70 6c 61 63 65 } 		$a_81_2 = {44 65 63 6f 6d 70 72 65 73 73 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}