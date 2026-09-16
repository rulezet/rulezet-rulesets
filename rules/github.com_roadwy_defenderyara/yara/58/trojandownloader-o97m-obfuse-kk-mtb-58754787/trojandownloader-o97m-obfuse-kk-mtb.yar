rule TrojanDownloader_O97M_Obfuse_KK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 22 72 65 74 75 72 6e 20 73 65 6c 65 63 74 43 6c 65 61 72 2e 73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b 7d 6d 61 69 6e 57 69 6e 64 6f 77 54 6d 70 20 3d 22 29 } 		$a_01_1 = {3d 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 64 65 6c 65 74 65 4d 61 69 6e 4d 61 69 6e 2e 68 74 61 22 } 		$a_01_2 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 67 65 74 77 63 29 2c 20 22 20 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}