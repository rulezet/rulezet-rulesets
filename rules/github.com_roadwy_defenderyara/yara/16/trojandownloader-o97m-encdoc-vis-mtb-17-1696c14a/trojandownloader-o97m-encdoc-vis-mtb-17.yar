rule TrojanDownloader_O97M_EncDoc_VIS_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 7a 78 63 2e 61 6d 69 72 61 6c 72 6f 75 74 65 72 2e 6f 6e 6c 69 6e 65 2f 74 65 73 74 78 78 78 78 2e 65 78 65 22 } 		$a_01_1 = {47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 2b 20 22 2f 73 65 72 76 65 2e 65 78 65 22 } 		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 54 65 6d 70 46 69 6c 65 2c 20 32 } 		$a_01_3 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 54 65 6d 70 46 69 6c 65 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}