rule TrojanDownloader_O97M_EncDoc_SSMA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-30] 29 20 2b 20 [0-25] 20 2b 20 22 5c 90 17 04 0f 09 08 04 64 65 66 69 6e 69 74 65 6c 79 64 65 73 74 69 74 75 74 65 64 65 66 69 6e 69 74 65 64 65 65 70 2e 6c 6e 6b 22 } 		$a_03_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-30] 29 20 26 20 [0-25] 20 2b 20 22 5c (64 65 64 75 63 74 69 6f 6e|64 65 66 65 6e 73 65) 2e 6c 6e 6b 22 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}