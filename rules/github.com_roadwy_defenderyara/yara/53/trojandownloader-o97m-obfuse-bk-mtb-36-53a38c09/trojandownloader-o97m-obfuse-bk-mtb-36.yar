rule TrojanDownloader_O97M_Obfuse_BK_MTB_36{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6d 6e 79 4a 6b 2e 70 64 66 22 } 		$a_01_1 = {62 74 4f 6c 78 28 50 44 4d 7a 67 29 2e 65 78 65 63 20 28 71 75 6c 64 64 29 } 		$a_01_2 = {3d 20 74 6a 64 49 4e 28 56 4d 6d 43 55 29 20 26 20 22 20 22 20 26 20 61 56 7a 4c 6b } 		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 47 7a 6b 42 4e 28 33 29 20 26 20 22 2e 22 20 26 20 47 7a 6b 42 4e 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}