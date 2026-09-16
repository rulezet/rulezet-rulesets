rule TrojanDownloader_O97M_Obfuse_BK_MTB_34{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 4e 6c 63 5a 6b 48 41 47 61 4b 2e 6d 78 71 6a 71 5a 68 57 51 49 54 6b 5f 70 5f 70 7a 68 5f 73 62 45 } 		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } 		$a_01_2 = {3d 20 6e 77 59 48 74 76 5f 4c 6a 2e 72 73 72 63 6c 4f 78 45 53 67 58 47 55 66 5a 58 49 53 53 70 72 } 		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}