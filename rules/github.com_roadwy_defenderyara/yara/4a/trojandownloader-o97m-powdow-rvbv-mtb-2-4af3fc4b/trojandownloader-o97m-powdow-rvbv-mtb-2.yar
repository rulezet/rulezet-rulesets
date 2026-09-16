rule TrojanDownloader_O97M_Powdow_RVBV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 68 65 6c 6c 65 78 65 63 75 74 65 64 66 67 64 66 6a 69 65 6a 66 6a 64 73 68 61 6a 2c 79 65 75 73 6b 61 6b 73 65 66 2c 22 22 2c 22 6f 70 65 6e 22 2c 30 65 6e 64 73 75 62 } 		$a_01_1 = {72 65 70 6c 61 63 65 28 64 66 67 64 66 6a 69 65 6a 66 6a 64 73 68 61 6a 2c 66 6a 64 6a 6b 61 73 66 2c 22 22 29 } 		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 73 65 74 64 6a 66 65 69 68 66 69 64 6b 61 73 6c 6a 66 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}