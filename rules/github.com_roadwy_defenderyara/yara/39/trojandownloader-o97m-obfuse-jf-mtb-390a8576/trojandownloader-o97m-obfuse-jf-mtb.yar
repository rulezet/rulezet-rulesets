rule TrojanDownloader_O97M_Obfuse_JF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } 		$a_03_1 = {43 61 6c 6c 20 [0-09] 28 [0-09] 2e [0-09] 2c 20 22 76 65 72 69 6e 73 74 65 72 65 2e 78 6c 73 22 2c 20 30 29 } 		$a_01_2 = {3d 20 56 42 41 2e 53 70 6c 69 74 28 22 22 29 } 		$a_01_3 = {3d 20 56 42 41 2e 4d 69 64 24 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}