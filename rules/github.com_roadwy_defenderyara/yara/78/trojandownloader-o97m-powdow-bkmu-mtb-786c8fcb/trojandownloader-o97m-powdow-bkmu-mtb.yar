rule TrojanDownloader_O97M_Powdow_BKMU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 76 75 6e 20 3d 20 6a 76 75 6e 20 26 } 		$a_01_1 = {2e 52 75 6e 28 6e 75 6a 76 66 74 69 64 78 2c 20 62 6c 6a 64 61 77 75 75 76 6d 79 6f 7a 6e 73 62 6b 71 75 6e 77 77 77 79 70 6c 64 71 78 62 6f 62 64 64 76 6c 62 29 } 		$a_01_2 = {63 6e 6c 2e 6a 76 78 } 		$a_01_3 = {6a 68 74 66 68 70 75 20 28 69 62 65 71 70 6d 6e 6e 7a 78 71 67 6b 73 75 6b 74 77 69 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}