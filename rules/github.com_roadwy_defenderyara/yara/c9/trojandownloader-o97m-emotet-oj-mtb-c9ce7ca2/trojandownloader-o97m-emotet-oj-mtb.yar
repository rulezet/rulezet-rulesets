rule TrojanDownloader_O97M_Emotet_OJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4d 75 6e 69 66 78 68 6c 75 71 73 28 [0-45] 28 22 [0-20] 77 [0-20] 69 [0-20] [0-20] 6e [0-20] 6d [0-20] 67 [0-20] 6d [0-20] 74 [0-20] 73 [0-20] 3a } 		$a_03_1 = {43 72 65 61 74 65 28 [0-45] 2c 20 [0-45] 2c } 		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-45] 2c 20 [0-45] 2c 20 22 22 29 } 		$a_01_3 = {2c 20 4d 53 46 6f 72 6d 73 2c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}