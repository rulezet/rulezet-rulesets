rule Trojan_BAT_AgentTesla_EM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4d 4f 48 42 41 44 2e 4d 4f 48 42 41 44 } 		$a_81_1 = {62 61 64 62 61 64 6d 6f 68 68 2e 74 78 74 } 		$a_81_2 = {4b 59 4f 2d 54 55 58 2d 47 49 4e 55 58 2d 46 49 4c 45 2d 54 59 50 45 53 2d 4a 50 45 47 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_4 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}