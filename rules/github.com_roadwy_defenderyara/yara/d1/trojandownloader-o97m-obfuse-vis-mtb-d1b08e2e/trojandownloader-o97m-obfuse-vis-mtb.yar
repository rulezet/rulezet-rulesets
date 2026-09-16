rule TrojanDownloader_O97M_Obfuse_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-72] 29 20 53 74 65 70 20 32 } 		$a_03_1 = {73 53 74 72 20 3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 [0-72] 2c 20 69 2c 20 32 29 29 20 2d 20 32 39 29 } 		$a_01_2 = {53 68 65 6c 6c 20 73 53 74 72 } 		$a_01_3 = {50 72 69 76 61 74 65 20 53 75 62 20 61 73 64 61 73 28 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}