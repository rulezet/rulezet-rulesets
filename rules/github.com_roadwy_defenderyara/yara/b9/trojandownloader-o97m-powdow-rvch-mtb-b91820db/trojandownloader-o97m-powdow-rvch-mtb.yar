rule TrojanDownloader_O97M_Powdow_RVCH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 39 39 39 4f 5f 50 2f 36 34 32 2e 34 39 31 2e 33 2e 32 39 31 2f 2f 3a 70 74 74 68 } 		$a_01_1 = {58 4e 46 6a 68 4c 2e 52 75 6e 20 22 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 2b 20 65 62 71 72 6e 20 2b 20 22 20 22 20 2b 20 79 4f 73 68 69 43 } 		$a_01_2 = {41 75 74 6f 5f 4f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}