rule TrojanDownloader_O97M_EncDoc_ALA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 73 71 6c 2e 67 67 2f 36 5f 61 52 5f 76 62 30 68 4f 5f 53 61 55 6e 47 37 56 68 76 77 53 6b 63 41 41 75 74 76 58 4a 41 2f 53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 65 72 76 69 63 65 2e 65 78 65 } 		$a_01_1 = {6d 79 46 69 6c 65 20 3d 20 22 5f 72 61 67 65 5f 65 78 65 63 2e 62 61 74 } 		$a_01_2 = {53 68 65 6c 6c 20 28 22 5f 72 61 67 65 5f 65 78 65 63 2e 62 61 74 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}