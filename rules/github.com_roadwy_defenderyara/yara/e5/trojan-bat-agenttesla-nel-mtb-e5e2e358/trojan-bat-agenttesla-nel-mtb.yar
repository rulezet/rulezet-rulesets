rule Trojan_BAT_AgentTesla_NEL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 78 69 57 65 62 5f 4d 53 70 72 74 } 		$a_01_1 = {48 50 5a 33 52 77 73 5f 57 65 62 5f 48 66 6f 33 32 } 		$a_01_2 = {6b 62 64 5f 50 6f 74 63 61 } 		$a_01_3 = {65 70 30 69 63 65 73 5f 50 72 6f 70 64 4d 74 70 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=12
 
}