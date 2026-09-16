rule TrojanDownloader_O97M_EncDoc_VI_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 39 31 2e 39 32 2e 31 30 39 2e 31 36 2f 69 6d 61 67 65 73 2f 72 65 64 74 61 6e 6b 2e 70 6e 67 } 		$a_01_2 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 74 65 73 74 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}