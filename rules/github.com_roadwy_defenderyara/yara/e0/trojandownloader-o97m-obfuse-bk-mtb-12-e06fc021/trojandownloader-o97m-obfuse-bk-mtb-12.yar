rule TrojanDownloader_O97M_Obfuse_BK_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 66 65 69 78 62 74 6f 20 2b 20 73 6f 31 20 2b 20 68 6f 32 20 2b 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 73 64 68 6a 61 36 37 78 7a 68 6a 64 61 73 22 } 		$a_01_1 = {3d 20 22 6d 22 } 		$a_01_2 = {3d 20 22 73 22 } 		$a_01_3 = {3d 20 22 68 22 } 		$a_01_4 = {53 68 65 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}