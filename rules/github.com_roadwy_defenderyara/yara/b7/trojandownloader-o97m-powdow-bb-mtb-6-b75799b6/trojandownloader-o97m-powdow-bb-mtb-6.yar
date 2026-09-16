rule TrojanDownloader_O97M_Powdow_BB_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 63 3a 5c 74 65 6d 70 5c 73 70 6f 6f 6c 2e 65 78 65 22 29 } 		$a_01_1 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 6d 6b 64 69 72 20 63 3a 5c 74 65 6d 70 22 29 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 73 53 6f 75 72 63 65 55 72 6c 2c 20 73 4c 6f 63 61 6c 46 69 6c 65 2c 20 42 49 4e 44 46 5f 47 45 54 4e 45 57 45 53 54 56 45 52 53 49 4f 4e 2c 20 30 26 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}