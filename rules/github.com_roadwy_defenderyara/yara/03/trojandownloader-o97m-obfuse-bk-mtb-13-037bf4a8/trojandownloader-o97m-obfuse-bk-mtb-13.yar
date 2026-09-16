rule TrojanDownloader_O97M_Obfuse_BK_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 73 62 6a 49 42 49 54 6c 48 38 53 4b 4c 62 49 42 5f 4b 2e 41 67 50 59 35 46 65 51 68 5f 65 44 75 79 36 35 75 76 54 75 45 64 } 		$a_01_1 = {68 67 72 74 20 3d 20 43 68 72 28 68 67 66 20 2d 20 37 29 } 		$a_01_2 = {3d 20 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 } 		$a_01_3 = {69 52 20 3d 20 69 52 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}