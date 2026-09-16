rule TrojanDownloader_O97M_Obfuse_BK_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 6e 45 41 61 63 79 57 79 70 4e 47 6e 73 6f 5f 55 71 51 4b 59 2e } 		$a_01_1 = {3d 20 49 73 44 61 74 65 28 49 73 4e 75 6d 65 72 69 63 } 		$a_01_2 = {3d 20 6e 45 41 61 63 79 57 79 70 4e 47 6e 73 6f 5f 55 71 51 4b 59 2e 6d 66 62 5a 48 6d 61 56 66 74 } 		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}