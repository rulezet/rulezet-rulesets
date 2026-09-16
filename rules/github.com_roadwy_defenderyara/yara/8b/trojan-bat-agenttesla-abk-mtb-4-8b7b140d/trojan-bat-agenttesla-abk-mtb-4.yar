rule Trojan_BAT_AgentTesla_ABK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {2b 08 2a 28 0a ?? ?? 06 2b f6 28 05 ?? ?? 06 2b f1 90 0a 18 00 72 13 ?? ?? 70 2b 03 } 		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } 		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } 		$a_01_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } 		$a_01_4 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } 		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}