rule TrojanDownloader_O97M_Obfuse_BK_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 5f 71 41 6c 7a 72 39 78 57 54 6a 35 2e 4f 68 58 50 6b 4a 32 73 6f 71 70 75 35 52 47 74 52 76 44 33 61 39 6b 64 } 		$a_01_1 = {2e 52 75 6e 28 76 41 77 6b 37 52 75 72 4e 72 53 44 61 36 4f 4d 50 72 51 52 57 64 44 42 43 59 34 63 77 6b 35 64 45 6f 57 56 66 65 6a 42 6e 6d 37 6e 6f 5a 64 5f 43 } 		$a_01_2 = {43 4c 20 3d 20 43 4c 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}