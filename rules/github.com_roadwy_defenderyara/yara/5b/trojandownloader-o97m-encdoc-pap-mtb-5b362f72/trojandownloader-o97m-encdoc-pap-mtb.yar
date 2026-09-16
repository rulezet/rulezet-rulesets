rule TrojanDownloader_O97M_EncDoc_PAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 62 5f 6e 61 6d 65 3d 22 90 17 03 03 03 02 6e 6d 71 6d 67 6b 7a 79 } 		$a_01_1 = {3d 30 6e 63 62 3d 22 76 62 78 63 62 62 6e 76 62 63 76 63 7a 78 63 76 78 63 62 76 78 63 62 22 } 		$a_01_2 = {26 76 62 6e 67 68 66 67 28 32 32 31 29 26 } 		$a_01_3 = {63 68 72 28 78 63 64 73 67 2d 31 34 34 29 78 63 76 62 76 78 63 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}