rule TrojanDownloader_BAT_AgentTesla_ABO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 2c 07 09 6f 1a ?? ?? 0a 00 dc 08 6f 1b ?? ?? 0a 13 04 de 16 90 0a 49 00 00 72 01 ?? ?? 70 28 04 ?? ?? 06 0a 06 73 15 ?? ?? 0a 0b 00 73 16 ?? ?? 0a 0c 00 07 16 73 17 ?? ?? 0a 73 18 ?? ?? 0a 0d 00 09 08 6f 19 ?? ?? 0a 00 00 de 0b } 		$a_01_1 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } 		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } 		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}