rule Trojan_BAT_AgentTesla_NFO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {04 04 02 7b } 		$a_01_1 = {04 8e 69 5d 93 03 61 d2 2a } 		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } 		$a_01_3 = {3c 4d 61 69 6e 3e 67 5f 5f 42 61 62 6f 7c 31 } 		$a_01_4 = {3c 3e 63 5f 5f 44 69 73 70 6c 61 79 43 6c 61 73 73 30 5f 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}