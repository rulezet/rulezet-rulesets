rule TrojanDownloader_O97M_Obfuse_BK_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 69 65 50 51 44 61 78 70 2e 4f 70 65 6e 20 6b 6f 4e 77 38 4d 41 72 4f 2c 20 4b 4d 68 6f 73 76 66 6e 62 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 50 61 73 73 77 6f 72 64 22 } 		$a_01_1 = {3d 20 22 68 74 74 70 73 3a 2f 2f 67 68 67 68 67 68 66 68 66 68 66 68 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 44 48 4c 20 51 41 2d 54 72 61 63 6b 65 72 2e 67 69 66 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}