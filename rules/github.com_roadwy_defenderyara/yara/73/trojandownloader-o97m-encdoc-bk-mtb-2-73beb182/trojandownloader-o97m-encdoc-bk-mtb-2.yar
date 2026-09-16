rule TrojanDownloader_O97M_EncDoc_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 75 74 65 64 69 67 69 74 61 6c 70 68 6f 74 6f 67 72 61 70 68 79 2e 63 6f 6d 2f 63 75 74 65 70 68 2f 70 68 6f 74 6f 73 6d 61 2e 70 68 70 } 		$a_01_1 = {43 3a 5c 62 63 65 6f 64 } 		$a_01_2 = {5c 65 77 66 76 73 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}