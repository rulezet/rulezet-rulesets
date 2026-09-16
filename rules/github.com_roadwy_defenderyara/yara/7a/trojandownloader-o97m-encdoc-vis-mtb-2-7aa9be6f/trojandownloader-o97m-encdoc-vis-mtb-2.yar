rule TrojanDownloader_O97M_EncDoc_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 54 6f 46 69 6c 65 41 } 		$a_01_1 = {2f 35 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } 		$a_01_2 = {65 78 70 6c 6f 72 65 72 30 } 		$a_01_3 = {43 3a 5c 44 72 6f 66 74 5c 46 72 6f 74 73 5c 5a 65 72 69 6f 44 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}