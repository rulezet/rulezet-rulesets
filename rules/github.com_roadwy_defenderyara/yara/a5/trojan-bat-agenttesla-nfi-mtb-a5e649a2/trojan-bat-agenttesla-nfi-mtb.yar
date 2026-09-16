rule Trojan_BAT_AgentTesla_NFI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 31 61 39 38 38 31 63 2d 37 38 38 37 2d 34 63 64 31 2d 61 66 31 37 2d 66 35 62 39 64 61 30 66 62 64 64 36 } 		$a_01_1 = {57 5d b6 c1 09 0b 00 00 00 fa 25 33 00 16 00 00 02 } 		$a_01_2 = {47 65 74 50 69 78 65 6c } 		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } 		$a_01_4 = {54 6f 57 69 6e 33 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}