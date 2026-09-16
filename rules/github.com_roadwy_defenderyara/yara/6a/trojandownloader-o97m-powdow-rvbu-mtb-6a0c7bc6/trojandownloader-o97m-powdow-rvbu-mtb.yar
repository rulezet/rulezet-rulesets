rule TrojanDownloader_O97M_Powdow_RVBU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 72 65 73 67 69 63 2f 6b 74 2e 67 64 63 65 69 66 76 2f 2f 3a 70 74 74 68 27 27 } 		$a_01_1 = {22 70 6f 77 65 22 20 2b 20 22 72 73 22 20 2b 20 52 61 6e 67 65 28 22 46 31 30 30 22 29 2e 56 61 6c 75 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}