rule TrojanDownloader_O97M_Obfuse_OP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 6d 6f 6e 69 63 61 70 65 63 65 72 65 2e 69 74 2f 4e 36 4e 77 51 48 52 39 52 49 50 6f 33 70 46 2e 65 78 65 22 } 		$a_01_1 = {2e 4f 70 65 6e 20 44 65 76 6c 70 2c 20 44 6f 77 6e 6c 6f 61 64 69 6d 61 67 65 5f 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 } 		$a_01_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 53 65 72 76 65 72 2e 67 69 66 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}