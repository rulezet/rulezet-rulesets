rule Trojan_BAT_AgentTesla_EA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 } 		$a_01_1 = {41 70 70 44 6f 6d 61 69 6e } 		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_01_3 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}