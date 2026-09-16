rule TrojanDownloader_O97M_EncDoc_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 73 61 22 26 22 6d 74 6e 70 79 2e 6f 72 67 2f 62 76 65 43 47 4b 54 58 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 2c 22 } 		$a_01_1 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 6d 22 26 22 61 73 73 22 26 22 6e 67 6f 2e 6f 72 67 2f 64 58 4b 76 79 4b 56 39 76 38 63 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 2c 22 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}