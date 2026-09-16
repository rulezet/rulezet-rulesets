rule TrojanDownloader_O97M_Obfuse_BK_MTB_28{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 4c 5f 5f 52 62 57 5f 61 4e 41 75 78 59 4f 5f 61 79 2e } 		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } 		$a_01_2 = {71 5a 48 6d 71 57 76 7a 56 2e 78 46 44 5f 69 6b 5f 5a 58 41 66 77 63 59 79 62 57 50 73 48 46 6a 48 5a 65 4e 44 } 		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}