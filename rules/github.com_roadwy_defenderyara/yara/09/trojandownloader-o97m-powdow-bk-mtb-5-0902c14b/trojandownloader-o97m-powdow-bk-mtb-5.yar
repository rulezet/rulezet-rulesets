rule TrojanDownloader_O97M_Powdow_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 7a 75 6e 4c 72 55 2e 52 75 6e 20 49 70 52 41 68 59 65 4a 20 2b 20 6e 59 4a 45 5a 4a 74 62 20 2b 20 79 4b 69 6a 6a 79 49 2c 20 52 56 61 6c 75 65 } 		$a_01_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 } 		$a_01_2 = {53 65 74 20 68 7a 75 6e 4c 72 55 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}