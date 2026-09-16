rule TrojanDownloader_O97M_EncDoc_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 62 6e 6d 2e 6e 61 76 65 72 63 6c 6f 75 64 2e 6f 72 67 2f 6d 6f 6e 67 6f 2f 72 74 76 77 69 79 64 6f 2e 67 69 66 } 		$a_01_1 = {3a 66 74 70 3a 2f 2f 6d 6f 6e 3a 64 62 40 } 		$a_01_2 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 6e 20 2f 73 20 2f 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}