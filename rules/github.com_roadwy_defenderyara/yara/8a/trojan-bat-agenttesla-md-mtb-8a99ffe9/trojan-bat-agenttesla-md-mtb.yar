rule Trojan_BAT_AgentTesla_MD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 26 06 09 08 09 08 8e 69 5d 91 07 09 91 61 d2 6f ?? ?? ?? 0a 09 13 04 2b 03 0c 2b e1 11 04 17 58 0d 2b 04 2c 0f 2b c5 09 07 8e 69 32 02 2b 05 } 		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 		$a_01_2 = {54 6f 41 72 72 61 79 } 		$a_01_3 = {47 65 74 42 79 74 65 73 } 		$a_01_4 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}