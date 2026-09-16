rule TrojanDownloader_O97M_EncDoc_VIS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 64 61 73 6a 69 73 64 75 61 69 73 6b 64 68 69 6b 68 61 73 64 } 		$a_01_1 = {52 75 6e 20 6c 6f 72 61 32 } 		$a_01_2 = {6d 73 68 74 61 } 		$a_01_3 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}