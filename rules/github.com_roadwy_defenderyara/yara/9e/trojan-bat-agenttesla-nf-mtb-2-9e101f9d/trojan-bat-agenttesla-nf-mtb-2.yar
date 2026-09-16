rule Trojan_BAT_AgentTesla_NF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 16 06 8e 69 28 ?? ?? ?? 0a 02 7b ?? ?? ?? 04 25 2d 02 26 2a 06 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 2a } 		$a_01_1 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } 		$a_01_2 = {49 6e 76 6f 6b 65 } 		$a_01_3 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}