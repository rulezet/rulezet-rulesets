rule TrojanDownloader_O97M_EncDoc_P_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.P!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 } 		$a_01_1 = {22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 39 2e 35 39 2e 32 35 33 2f 63 75 74 2f 32 39 30 30 39 31 33 33 32 38 35 30 39 38 36 2e 62 61 74 } 		$a_01_2 = {4a 7a 71 74 64 65 75 68 76 6f 63 68 77 79 73 69 65 6a 69 6e 6c 6c 6b 2e 65 78 65 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}