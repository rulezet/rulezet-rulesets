rule Trojan_BAT_AgentTesla_EZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {23 54 68 69 73 2d 77 6f 72 6c 64 2d 68 61 76 65 2d 6d 61 6e 79 2d 74 68 69 6e 67 73 } 		$a_81_1 = {23 4c 65 61 72 6e 2d 65 76 65 72 79 74 68 69 6e 67 2d 62 79 2d 68 65 61 72 74 } 		$a_81_2 = {23 46 75 63 6b 2d 74 68 69 73 2d 73 6f 63 69 65 74 79 } 		$a_81_3 = {23 59 69 6b 65 73 2d 73 6b 69 64 73 } 		$a_81_4 = {23 4d 65 6f 77 74 72 69 78 48 61 78 6f 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}