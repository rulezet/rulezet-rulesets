rule TrojanDownloader_O97M_Obfuse_BK_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 65 58 6d 61 50 65 61 4b 2e 6f 74 39 5f 59 6c 51 5f 4e 77 37 6c 56 42 75 70 66 5f 50 54 } 		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } 		$a_01_2 = {2e 52 75 6e 28 44 67 69 39 5f 42 63 75 67 55 59 74 36 5f 2c 20 47 4a 57 37 5a 5f 53 42 72 31 5f 57 78 67 4a 41 59 33 63 55 45 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}