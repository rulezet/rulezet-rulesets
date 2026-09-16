rule Trojan_BAT_AgentTesla_MY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b [0-07] 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 [0-12] 17 58 13 04 11 04 06 8e 69 32 ?? 09 2a } 		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 		$a_01_2 = {47 65 74 42 79 74 65 73 } 		$a_01_3 = {54 6f 41 72 72 61 79 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}