rule TrojanDownloader_O97M_Powdow_RVBQ_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 70 6c 61 63 65 28 22 63 6d 64 2f 63 70 6f 77 5e 61 6e 73 65 79 65 6e 38 72 73 5e 68 61 6e 73 65 79 65 6e 38 6c 6c 2f 77 30 31 63 5e 75 5e 72 6c 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 61 6e 73 65 79 65 6e 38 72 2e 73 68 2f 67 61 6e 73 65 79 65 6e 38 74 2f 77 75 72 39 66 66 2f 62 75 69 6c 64 2e 61 6e 73 65 79 65 6e 38 5e 78 61 6e 73 65 79 65 6e 38 2d 6f 22 26 6f 6c 36 71 26 22 3b 22 26 6f 6c 36 71 2c 22 61 6e 73 65 79 65 6e 38 22 2c 22 65 22 29 66 74 6b 76 63 68 2e 65 78 65 } 		$a_01_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}