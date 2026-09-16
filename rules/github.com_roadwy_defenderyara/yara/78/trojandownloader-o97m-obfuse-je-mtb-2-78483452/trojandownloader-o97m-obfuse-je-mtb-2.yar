rule TrojanDownloader_O97M_Obfuse_JE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } 		$a_03_1 = {29 20 26 20 22 23 22 [0-02] 4e 65 78 74 } 		$a_03_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-40] 29 20 53 74 65 70 20 32 [0-02] 4d 69 64 28 } 		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-40] 2c 20 22 23 22 2c 20 22 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}