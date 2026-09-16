rule TrojanDownloader_O97M_EncDoc_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 50 69 71 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6e 31 29 } 		$a_01_1 = {50 69 71 70 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 43 65 6c 6c 73 28 37 2c 20 31 29 2c 20 66 6a 64 66 6b 28 41 32 29 2c 20 22 22 2c 20 22 22 2c 20 30 } 		$a_01_2 = {50 4a 63 56 74 7a 20 3d 20 52 69 67 68 74 28 4c 65 66 74 28 67 6f 46 67 7a 63 45 2c 20 6b 6b 29 2c 20 32 20 2d 20 31 29 20 26 20 62 76 67 42 49 63 4a 75 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}