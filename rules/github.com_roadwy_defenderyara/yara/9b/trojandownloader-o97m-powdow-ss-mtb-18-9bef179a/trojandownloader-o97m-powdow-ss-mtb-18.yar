rule TrojanDownloader_O97M_Powdow_SS_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 54 65 6d 70 44 69 72 3b 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } 		$a_01_1 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 73 65 76 65 63 61 2d 65 6d 69 6c 69 61 2f 6f 6e 65 6d 6f 72 65 73 6c 61 76 65 2f 64 6f 77 6e 6c 6f 61 64 73 2f 73 7a 2e 65 78 65 27 2c } 		$a_01_2 = {24 54 65 6d 70 44 69 72 2b 27 74 65 73 74 2e 65 78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 74 65 73 74 2e 65 78 65 27 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}