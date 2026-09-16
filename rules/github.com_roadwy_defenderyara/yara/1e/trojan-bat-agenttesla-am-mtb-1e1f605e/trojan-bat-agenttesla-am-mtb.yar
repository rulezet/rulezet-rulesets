rule Trojan_BAT_AgentTesla_AM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 72 35 01 ?? 70 28 1a ?? ?? 06 0b 73 49 ?? ?? 0a 0c 07 8e 69 13 06 2b 13 00 16 2d 0a 08 07 11 06 91 } 		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 		$a_01_3 = {54 6f 41 72 72 61 79 } 		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}