rule Trojan_BAT_AgentTesla_LNA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d de 15 } 		$a_01_1 = {00 45 78 61 6d 70 6c 65 00 67 65 74 5f 4e 61 6d 65 00 } 		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } 		$a_01_3 = {54 6f 42 79 74 65 41 72 72 61 79 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}