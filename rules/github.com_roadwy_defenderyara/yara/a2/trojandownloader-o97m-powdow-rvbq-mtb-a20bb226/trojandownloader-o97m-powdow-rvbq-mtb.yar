rule TrojanDownloader_O97M_Powdow_RVBQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 22 2b 22 73 22 2b 22 63 22 2b 22 72 22 2b 22 69 22 2b 22 70 22 2b 22 74 22 2b 22 2e 22 2b 22 73 22 2b 22 68 22 2b 22 65 22 2b 22 6c 22 2b 22 6c 22 29 } 		$a_01_1 = {63 6c 6f 73 65 74 65 78 74 66 69 6c 65 3d 73 68 6f 77 74 65 78 74 66 69 6c 65 5f 2e 5f 73 68 6f 77 62 61 72 2e 5f 74 61 67 2b 5f 73 68 6f 77 74 65 78 74 66 69 6c 65 5f 2e 5f 66 72 61 6d 65 31 31 2e 5f 74 61 67 65 6e 64 73 75 62 } 		$a_01_2 = {73 75 62 5f 61 75 74 6f 5f 63 6c 6f 73 65 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}