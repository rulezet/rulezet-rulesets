rule TrojanDownloader_O97M_EncDoc_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 71 44 77 49 66 44 42 71 59 20 3d 20 6c 63 43 72 4a 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 4f 54 44 5a 20 2b 20 22 5c 6e 52 53 64 72 2e 76 62 73 22 2c 20 38 2c 20 54 72 75 65 29 } 		$a_01_1 = {45 6e 64 54 69 63 6b 20 3d 20 47 65 74 54 69 63 6b 43 6f 75 6e 74 20 2b 20 28 46 69 6e 69 73 68 20 2a 20 31 30 30 30 29 } 		$a_01_2 = {4f 54 44 5a 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}