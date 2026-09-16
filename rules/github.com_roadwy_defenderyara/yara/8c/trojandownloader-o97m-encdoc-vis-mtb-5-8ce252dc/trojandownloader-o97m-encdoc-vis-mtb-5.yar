rule TrojanDownloader_O97M_EncDoc_VIS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5f } 		$a_01_1 = {41 75 74 6f 5f 63 6c 6f 73 65 28 29 } 		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } 		$a_03_3 = {53 68 65 6c 6c 20 [0-70] 2e 54 61 67 } 		$a_01_4 = {55 6e 6c 6f 61 64 20 4d 65 } 		$a_01_5 = {54 65 72 6d 69 6e 61 74 65 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}