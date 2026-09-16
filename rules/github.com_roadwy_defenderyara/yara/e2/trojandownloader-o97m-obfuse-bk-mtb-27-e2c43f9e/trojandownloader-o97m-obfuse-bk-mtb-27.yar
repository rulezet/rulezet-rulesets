rule TrojanDownloader_O97M_Obfuse_BK_MTB_27{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 64 72 63 34 53 72 75 31 48 52 4c 65 65 63 75 44 4e 77 6e 78 32 51 34 61 2e 72 44 75 49 71 5f 41 6c 5f 32 6b 41 5f 43 35 76 32 70 5f 62 72 72 74 } 		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 47 69 73 50 35 41 4a 31 33 4e 6e 5f 55 59 37 34 79 39 51 73 59 58 52 45 52 74 42 58 38 56 38 7a 41 52 58 35 6a 55 } 		$a_01_2 = {2e 52 75 6e 28 74 48 64 41 6c 41 31 69 4a 4e 72 4d 55 51 5a 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}