rule TrojanDownloader_O97M_EncDoc_VIS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 75 4d 35 6c 65 5f 5f 5f 69 5f 43 6d 6f 39 5f 46 6c 35 2c 20 62 37 45 56 6d 51 66 5f 52 43 5f 4d 37 35 5f 46 7a 29 } 		$a_01_1 = {78 63 76 62 5f 20 3d 20 43 68 72 28 73 64 5f 20 2d 20 36 32 29 } 		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 70 63 5f 5f 5f 71 5f 5a 5f 63 6f 72 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}