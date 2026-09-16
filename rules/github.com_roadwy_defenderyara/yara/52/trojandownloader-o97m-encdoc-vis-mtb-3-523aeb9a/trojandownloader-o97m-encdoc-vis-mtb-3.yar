rule TrojanDownloader_O97M_EncDoc_VIS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5f } 		$a_01_1 = {41 75 74 6f 5f 63 6c 6f 73 65 28 29 } 		$a_03_2 = {44 69 6d 20 [0-09] 20 41 73 20 4e 65 77 20 73 65 78 } 		$a_03_3 = {53 68 65 6c 6c 20 73 65 78 2e [0-20] 2e [0-20] 2e 54 61 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}