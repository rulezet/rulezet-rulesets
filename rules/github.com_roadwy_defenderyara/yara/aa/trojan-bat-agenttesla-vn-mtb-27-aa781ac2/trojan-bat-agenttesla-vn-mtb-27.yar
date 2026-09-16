rule Trojan_BAT_AgentTesla_VN_MTB_27{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4d 69 6e 69 5f 47 61 6d 65 5f 43 65 6e 74 65 72 2e 4d 79 } 		$a_81_1 = {73 6e 61 6b 65 47 61 6d 65 4f 76 65 72 } 		$a_81_2 = {4d 69 6e 69 5f 47 61 6d 65 5f 43 65 6e 74 65 72 2e 73 6e 61 6b 65 2e 72 65 73 6f 75 72 63 65 73 } 		$a_81_3 = {24 37 31 38 30 62 38 61 34 2d 62 31 64 65 2d 34 37 35 39 2d 62 33 39 64 2d 33 32 64 35 65 65 32 37 36 34 30 38 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}