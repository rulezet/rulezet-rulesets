rule Trojan_BAT_AgentTesla_AM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 57 96 b6 2b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 } 		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } 		$a_01_2 = {73 65 74 5f 55 73 65 41 6e 74 69 41 6c 69 61 73 } 		$a_01_3 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}