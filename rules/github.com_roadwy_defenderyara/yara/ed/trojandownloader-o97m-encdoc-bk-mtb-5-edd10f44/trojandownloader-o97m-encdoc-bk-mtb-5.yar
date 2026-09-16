rule TrojanDownloader_O97M_EncDoc_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } 		$a_00_1 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 63 72 79 70 74 6f 70 72 6f 2e 67 61 2f 46 69 6c 65 2f 61 70 6f 2e 65 78 65 27 2c 27 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 79 61 74 61 67 65 2e 65 78 65 27 29 3b } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}