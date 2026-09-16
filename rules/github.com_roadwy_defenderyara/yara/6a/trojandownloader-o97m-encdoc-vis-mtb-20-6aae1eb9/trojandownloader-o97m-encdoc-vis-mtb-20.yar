rule TrojanDownloader_O97M_EncDoc_VIS_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c 20 46 61 6c 73 65 2c 20 42 79 56 61 6c 20 53 74 72 50 74 72 28 22 68 74 74 70 3a 2f 2f 31 39 32 2e 32 33 36 2e 31 34 37 2e 31 38 39 2f 65 78 65 63 75 74 65 2f 75 70 6c 6f 61 64 73 2f 45 78 63 65 6c 2e 73 63 74 22 29 20 27 20 46 61 6c 73 65 20 3d 20 22 44 6f 6e 27 74 20 69 6e 73 74 61 6c 6c } 		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 		$a_01_2 = {75 6e 63 74 69 6f 6e 20 44 6c 6c 49 6e 73 74 61 6c 6c 20 4c 69 62 20 22 73 63 72 6f 62 6a 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}