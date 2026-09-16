rule TrojanDownloader_O97M_Obfuse_BB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 6d 61 69 6e 2e 72 28 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 72 65 64 4c 69 6e 65 53 65 61 2e 68 74 22 29 } 		$a_01_1 = {2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 25 5f 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c } 		$a_01_2 = {2e 72 75 6e 20 6c 69 6e 65 4c 6f 76 65 4c 61 64 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}