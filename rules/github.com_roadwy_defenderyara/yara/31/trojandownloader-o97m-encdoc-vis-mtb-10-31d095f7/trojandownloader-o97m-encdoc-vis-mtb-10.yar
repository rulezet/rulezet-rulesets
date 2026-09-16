rule TrojanDownloader_O97M_EncDoc_VIS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 58 41 37 36 39 4f 6e 4a 49 72 5f 37 71 75 2c 20 63 51 5f 4c 4c 50 5f 6c 32 79 56 48 65 62 5f 76 29 } 		$a_01_1 = {78 63 76 62 5f 20 3d 20 43 68 72 28 73 64 5f 20 2d 20 36 32 29 } 		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 4c 5f 46 5a 69 6c 50 4b 70 53 53 49 5f 5f 4b 66 5f 4b 67 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}