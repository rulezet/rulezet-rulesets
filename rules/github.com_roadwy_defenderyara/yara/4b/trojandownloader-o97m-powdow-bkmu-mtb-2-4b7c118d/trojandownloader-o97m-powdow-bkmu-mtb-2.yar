rule TrojanDownloader_O97M_Powdow_BKMU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 76 70 20 3d 20 6f 76 70 20 26 } 		$a_01_1 = {7a 73 6e 6c 78 67 68 6f 7a 79 6e 61 6a 62 74 70 75 74 77 76 71 74 67 72 62 72 6c 61 72 6a 62 61 75 61 20 28 76 66 6a 66 73 66 76 79 6a 61 6a 69 79 75 62 74 66 29 } 		$a_01_2 = {73 77 6c 2e 7a 7a 61 78 } 		$a_01_3 = {2e 52 75 6e 28 75 75 73 7a 73 72 78 6b 6e 6b 7a 6a 73 63 65 73 74 75 2c 20 6f 73 74 74 79 71 6b 6d 67 62 6b 67 68 68 6c 71 77 79 67 74 79 6e 63 79 65 78 75 66 74 74 76 78 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}