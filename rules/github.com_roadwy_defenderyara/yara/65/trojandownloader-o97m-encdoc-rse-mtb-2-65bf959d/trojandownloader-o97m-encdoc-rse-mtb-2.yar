rule TrojanDownloader_O97M_EncDoc_RSE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 4d 64 2e 65 58 65 20 20 2f 63 20 50 6f 77 45 52 53 68 65 6c 6c 20 20 2d 65 78 20 62 79 70 41 73 73 20 2d 6e 6f 50 20 2d 77 20 31 20 69 65 58 28 20 } 		$a_00_1 = {63 55 72 6c 20 20 28 27 68 74 74 70 3a 2f 2f 63 72 69 74 69 27 20 20 2b 20 27 63 64 6f 6d 65 2e 63 6f 6d 2f 63 73 27 20 20 2b 20 27 73 73 2e 27 20 20 2b 20 27 6a 70 27 20 20 2b 20 27 67 27 20 29 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}