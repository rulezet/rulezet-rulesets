rule TrojanDownloader_O97M_EncDoc_VIS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 20 53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 3a } 		$a_01_1 = {43 61 6c 63 20 3d 20 5f } 		$a_01_2 = {45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31 } 		$a_01_3 = {3d 20 53 68 65 6c 6c 28 43 61 6c 63 2c 20 31 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}