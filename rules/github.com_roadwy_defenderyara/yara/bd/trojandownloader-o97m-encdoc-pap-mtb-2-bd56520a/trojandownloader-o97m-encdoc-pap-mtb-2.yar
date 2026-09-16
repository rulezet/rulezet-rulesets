rule TrojanDownloader_O97M_EncDoc_PAP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 3d 73 74 72 72 65 76 65 72 73 65 28 22 63 6e 65 2d 31 6e 69 77 2d 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 5c 30 2e 31 76 } 		$a_01_1 = {78 3d 78 2b 22 73 74 22 78 3d 78 2b 22 61 72 74 22 78 3d 78 2b 22 2f 6d 22 2b 22 69 22 2b 22 6e 22 70 72 65 66 69 78 31 3d 78 65 6e 64 } 		$a_01_2 = {64 3d 73 68 65 6c 6c 28 62 61 74 2c 30 29 65 6e 64 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}