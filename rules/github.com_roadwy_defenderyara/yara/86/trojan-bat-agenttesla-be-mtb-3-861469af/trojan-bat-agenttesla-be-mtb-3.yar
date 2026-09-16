rule Trojan_BAT_AgentTesla_BE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.BE!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 69 74 74 73 62 75 72 67 68 31 32 4d 6f 64 65 } 		$a_01_1 = {74 78 74 53 74 6f 72 65 5f 4b 65 79 44 6f 77 6e } 		$a_01_2 = {4e 6f 53 70 61 63 65 43 6f 70 79 54 65 78 74 42 6f 78 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}