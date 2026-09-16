rule TrojanDownloader_O97M_Obfuse_RO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 } 		$a_01_1 = {31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 } 		$a_03_2 = {2e 52 75 6e 20 22 22 20 2b 20 [0-60] 20 2b 20 22 20 22 20 2b } 		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-60] 2c 20 22 } 		$a_03_4 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-60] 29 [0-15] 4d 69 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}