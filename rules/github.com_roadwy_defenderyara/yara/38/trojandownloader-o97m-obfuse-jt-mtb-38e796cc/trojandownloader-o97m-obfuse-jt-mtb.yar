rule TrojanDownloader_O97M_Obfuse_JT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-04] 2c } 		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 22 74 65 73 74 22 2c 20 22 74 65 73 74 22 2c 20 43 68 72 28 [0-06] 29 29 } 		$a_01_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}