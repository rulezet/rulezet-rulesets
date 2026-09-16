rule TrojanDownloader_O97M_Qakbot_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_01_1 = {43 3a 5c 43 4f 73 75 76 5c 57 65 67 65 72 62 5c 73 7a 76 4d 68 65 67 6e 2e 65 78 65 } 		$a_01_2 = {55 52 4c 4d 6f 6e } 		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 		$a_01_4 = {68 74 74 70 3a 2f 2f 74 61 6b 2d 74 69 6b 2e 73 69 74 65 2f 63 72 75 6e 32 30 2e 67 69 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=12
 
}