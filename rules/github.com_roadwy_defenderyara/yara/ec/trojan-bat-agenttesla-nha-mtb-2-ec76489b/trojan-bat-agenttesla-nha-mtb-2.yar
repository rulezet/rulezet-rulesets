rule Trojan_BAT_AgentTesla_NHA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 20 10 0f 00 00 28 ?? ?? ?? 06 5a 20 ?? ?? ?? 00 28 ?? ?? ?? 06 61 38 ?? ?? ?? ff 02 20 ?? ?? ?? 00 28 ?? ?? ?? 06 2b 00 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a } 		$a_01_1 = {54 52 46 53 47 42 56 43 58 46 44 } 		$a_01_2 = {4d 4a 43 4b 56 4b 4c 55 49 4f 52 } 		$a_01_3 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}