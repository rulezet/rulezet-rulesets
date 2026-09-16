rule TrojanDownloader_O97M_Powdow_RVCA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 37 32 63 32 34 64 64 35 2d 64 37 30 61 2d 34 33 38 62 2d 38 61 34 32 2d 39 38 34 32 34 62 38 38 61 66 62 38 7d 22 29 3a 3a 3a 3a 3a 73 65 74 72 3d 5f 2e 5f 5f 65 78 65 63 [0-01] 28 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62 } 		$a_01_1 = {78 78 78 78 78 78 6c 6f 72 61 3d 2e 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 2b 2e 32 2e 76 61 6c 75 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 2e 70 72 69 6e 74 } 		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}