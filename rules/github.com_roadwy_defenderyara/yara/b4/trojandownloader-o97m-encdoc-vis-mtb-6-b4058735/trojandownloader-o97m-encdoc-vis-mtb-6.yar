rule TrojanDownloader_O97M_EncDoc_VIS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f } 		$a_01_1 = {70 6f 77 65 72 73 68 44 } 		$a_01_2 = {68 74 74 70 73 3a 2f 2f 74 68 65 70 68 6f 74 6f 67 72 61 70 68 65 72 73 77 6f 72 6b 66 6c 6f 77 2e 63 6f 6d 2f 76 76 2f 70 6f 70 69 2e 65 78 65 } 		$a_01_3 = {61 2e 62 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}