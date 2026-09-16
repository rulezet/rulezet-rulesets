rule TrojanDownloader_O97M_Obfuse_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 76 34 67 73 69 50 6c 5f 33 2e 67 6c 76 67 33 58 49 74 70 73 41 4c 43 75 38 37 5f 67 70 32 4b 38 41 48 65 65 35 69 6d } 		$a_01_1 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } 		$a_01_2 = {49 6d 20 3d 20 49 6d 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}