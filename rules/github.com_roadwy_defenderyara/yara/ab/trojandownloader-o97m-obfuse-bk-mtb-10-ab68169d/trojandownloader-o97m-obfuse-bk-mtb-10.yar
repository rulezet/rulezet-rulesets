rule TrojanDownloader_O97M_Obfuse_BK_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 37 4b 5f 5a 64 4b 57 59 77 44 68 69 61 4d 53 5f 68 34 5f 44 38 59 6d 5f 39 39 2e 57 34 36 5f 6d 57 65 67 4b 53 56 7a 5f 77 75 5f 46 32 6f 56 54 55 6a 49 55 4b 45 51 45 } 		$a_01_1 = {71 38 20 3d 20 71 38 20 26 20 } 		$a_01_2 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}