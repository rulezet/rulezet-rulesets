rule TrojanDownloader_O97M_Obfuse_BK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 35 45 4e 5f 2e 53 6f 64 55 75 78 5f 52 45 70 5f 5f 5a 5f 41 52 43 71 79 50 } 		$a_01_1 = {76 63 62 20 3d 20 43 68 72 28 61 73 64 20 2d 20 37 29 } 		$a_01_2 = {2e 52 75 6e 28 4f 79 6e 49 77 74 34 4e 59 73 58 51 48 55 2c 20 66 75 37 55 68 47 61 55 70 41 68 52 61 72 5a 45 49 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}