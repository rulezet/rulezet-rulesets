rule TrojanDownloader_O97M_Qakbot_PUH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 72 69 73 6e 6f } 		$a_00_1 = {5c 69 73 6e 6f 73 2e 65 78 65 } 		$a_00_2 = {70 66 6c 64 72 } 		$a_00_3 = {74 65 54 68 65 43 61 6c 6c } 		$a_00_4 = {4a 4a 43 43 43 4a 4a } 		$a_00_5 = {68 74 74 70 73 3a 2f 2f 64 37 66 76 38 69 75 33 6f 76 6e 2e 78 79 7a 2f 69 6e 64 65 78 2e 70 68 70 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}