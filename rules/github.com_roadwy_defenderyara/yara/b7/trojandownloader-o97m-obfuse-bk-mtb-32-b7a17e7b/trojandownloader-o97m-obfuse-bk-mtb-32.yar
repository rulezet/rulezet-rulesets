rule TrojanDownloader_O97M_Obfuse_BK_MTB_32{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 50 53 66 5f 69 45 59 4c 5f 4b 6f 48 65 73 6a 55 42 6c 55 67 48 4e 75 63 5f 6c 57 2e } 		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } 		$a_01_2 = {3d 20 49 73 41 72 72 61 79 28 49 73 4e 75 6d 65 72 69 63 28 } 		$a_01_3 = {3d 20 67 74 6c 5f 5f 4f 45 66 71 76 5f 67 48 42 7a 56 52 5a 45 49 62 75 6c 7a 6e 5f 61 70 64 62 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}