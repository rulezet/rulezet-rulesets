rule TrojanDownloader_BAT_AgentTesla_ABM_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 06 8e 69 1d 2d 09 26 2b 12 0a 2b eb 0b 2b f1 0c 2b f5 90 0a 2a 00 02 72 57 ?? ?? 70 28 0b ?? ?? 06 1a 2d 13 26 73 34 ?? ?? 0a 1b 2d 0d } 		$a_01_1 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 		$a_01_3 = {54 6f 41 72 72 61 79 } 		$a_01_4 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}