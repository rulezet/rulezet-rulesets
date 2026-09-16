rule Trojan_BAT_AgentTesla_NXX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {34 38 6d 43 4f 42 6b 50 54 4d 57 47 68 4a 68 54 53 65 37 64 52 31 67 6d 6a 78 71 68 } 		$a_81_1 = {4d 4b 35 4b 47 58 6f 36 6f 45 6b 43 51 52 42 52 42 62 76 2f 61 } 		$a_81_2 = {77 68 44 79 4f 32 4e 54 6b 64 4c 37 2f 53 71 4b 65 76 4f 37 2b 69 72 6a 6f 55 79 35 } 		$a_81_3 = {34 74 70 49 75 71 71 46 5a 67 73 73 65 49 5a 4f 38 70 66 4b 67 6f 2f 32 50 53 61 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}