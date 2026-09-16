rule Trojan_BAT_AgentTesla_AQC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 03 08 03 ?? ?? ?? ?? ?? 5d 17 d6 ?? ?? ?? ?? ?? da 0d 06 09 ?? ?? ?? ?? ?? 13 04 12 04 ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 0a 00 08 17 d6 0c 08 07 fe 02 16 fe 01 13 05 11 05 2d be 06 13 06 2b 00 11 06 2a } 		$a_80_1 = {47 65 74 54 79 70 65 } 		$a_80_2 = {4c 61 74 65 42 69 6e 64 69 6e 67 } 		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}