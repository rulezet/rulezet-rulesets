rule TrojanDownloader_O97M_Obfuse_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 7a 7a 68 5f 62 36 34 20 3d 20 7a 7a 7a 7a 68 5f 62 36 34 20 26 } 		$a_01_1 = {22 2f 6c 61 73 64 77 65 2f 62 64 61 61 33 38 31 31 2d 62 62 36 63 2d 34 32 63 37 2d 61 65 32 35 2d 30 33 32 39 66 33 61 35 39 63 65 31 22 2c 20 34 33 36 2c 20 7a 7a 7a 7a 68 } 		$a_01_2 = {44 79 6e 4d 65 6d 63 70 79 20 61 6c 6c 6f 63 2c 20 7a 7a 7a 7a 68 2c 20 68 72 65 61 64 2c 20 68 77 72 69 74 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}