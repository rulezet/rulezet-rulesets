rule Trojan_BAT_AgentTesla_AT_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 65 5f 44 72 6f 70 70 65 72 5f 31 } 		$a_01_1 = {4d 4e 4a 4b 6f 6c 4b 38 37 2e 70 64 62 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 } 		$a_01_3 = {66 36 66 61 38 38 36 64 2d 35 36 38 39 2d 34 32 34 33 2d 38 38 39 38 2d 36 32 37 61 37 39 62 34 35 36 36 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}