rule TrojanDownloader_O97M_Obfuse_BK_MTB_47{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 4d 4c 48 54 54 50 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 3a 2f 2f 6e 61 64 69 6d 2e 77 6f 72 6b 2f 64 65 6d 6f 2e 64 6f 63 22 2c 20 22 5c 22 2c 20 22 2f 22 29 2c 20 22 46 61 6c 73 65 22 } 		$a_01_1 = {41 44 4f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 74 6d 70 2e 64 6f 63 22 2c 20 32 } 		$a_01_2 = {46 69 6c 65 4e 61 6d 65 3a 3d 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 74 6d 70 2e 64 6f 63 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}