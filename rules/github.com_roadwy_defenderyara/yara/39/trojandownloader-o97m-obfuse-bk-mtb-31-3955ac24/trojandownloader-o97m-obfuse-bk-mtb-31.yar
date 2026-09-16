rule TrojanDownloader_O97M_Obfuse_BK_MTB_31{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 50 63 71 77 73 5f 4f 46 6d 55 49 73 6a 69 62 59 55 6b 2e } 		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } 		$a_01_2 = {3d 20 50 63 71 77 73 5f 4f 46 6d 55 49 73 6a 69 62 59 55 6b 2e 53 49 48 49 54 73 4a 4c 68 68 56 67 54 50 6b 41 4f 59 4f 76 68 } 		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}