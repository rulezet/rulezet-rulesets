rule TrojanDownloader_O97M_EncDoc_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 6d 73 68 74 61 22 2c 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 71 77 64 77 64 73 66 76 63 78 76 63 63 76 22 2c 20 22 22 2c 20 22 22 2c 20 30 } 		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}