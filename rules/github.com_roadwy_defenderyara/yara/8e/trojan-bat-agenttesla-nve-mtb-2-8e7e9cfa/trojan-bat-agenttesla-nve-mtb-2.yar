rule Trojan_BAT_AgentTesla_NVE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 38 00 00 0a 25 26 26 11 0a 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 13 10 7e ?? ?? ?? 04 11 10 16 11 10 28 ?? ?? ?? 06 25 26 69 6f ?? ?? ?? 0a } 		$a_01_1 = {42 56 4e 42 4d 48 4a 47 } 		$a_01_2 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } 		$a_01_3 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}