rule TrojanDownloader_O97M_Obfuse_BKO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 } 		$a_01_1 = {2e 52 75 6e 28 73 6f 68 6d 71 79 76 61 62 6a 2c 20 72 73 79 64 77 6d 62 6b 68 69 66 78 63 29 } 		$a_01_2 = {7a 76 69 63 20 3d 20 7a 76 69 63 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}