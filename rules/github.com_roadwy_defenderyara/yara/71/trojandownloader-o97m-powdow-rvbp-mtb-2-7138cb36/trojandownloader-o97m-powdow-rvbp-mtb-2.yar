rule TrojanDownloader_O97M_Powdow_RVBP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 5f 6f 70 65 6e 28 29 63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 21 28 2b 2c 76 62 68 69 64 65 29 65 6e 64 66 75 6e 63 74 69 6f 6e } 		$a_01_1 = {76 61 6c 28 6d 69 64 28 73 74 72 72 65 76 65 72 73 65 28 6e 75 6d 62 65 72 29 2c 69 2b 31 2c 31 29 29 } 		$a_01_2 = {3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 64 65 63 72 79 70 74 65 70 69 28 22 6a 22 29 2c 64 65 63 72 79 70 74 65 70 69 28 22 74 22 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}