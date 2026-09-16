rule TrojanDownloader_O97M_Obfuse_SJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f [0-25] 2f 6c 73 61 73 73 2e 65 78 65 22 } 		$a_01_1 = {6c 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 2b 20 22 5c 6c 73 61 73 73 2e 65 78 65 22 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } 		$a_03_3 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-05] 2c 20 46 61 6c 73 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}