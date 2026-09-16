rule Trojan_BAT_AgentTesla_EQS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 08 95 28 ?? ?? ?? 0a 0d 09 8e 69 17 da 13 04 16 13 05 2b 12 06 08 1a d8 11 05 d6 09 11 05 91 9c 11 05 17 d6 13 05 11 05 11 04 31 e8 08 17 d6 0c } 		$a_03_1 = {06 08 02 08 91 03 08 03 6f ?? ?? ?? 30 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 9c 08 17 d6 0c } 		$a_01_2 = {00 47 65 74 4d 65 74 68 6f 64 00 } 		$a_01_3 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}