rule TrojanDownloader_O97M_Obfuse_BK_MTB_30{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 6d 5f 52 75 78 59 50 42 53 6b 4c 41 45 6d 51 47 73 74 6f 52 76 59 5f 6c 58 57 70 50 52 4d 2e } 		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } 		$a_01_2 = {3d 20 46 79 43 4b 70 66 64 55 53 58 67 74 78 6e 5f 56 58 68 2e 70 6a 5f 63 71 7a 68 } 		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}