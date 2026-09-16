rule TrojanDownloader_O97M_EncDoc_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f 27 2c 27 61 2e 62 61 } 		$a_01_1 = {70 6f 77 65 72 73 68 44 } 		$a_01_2 = {6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}