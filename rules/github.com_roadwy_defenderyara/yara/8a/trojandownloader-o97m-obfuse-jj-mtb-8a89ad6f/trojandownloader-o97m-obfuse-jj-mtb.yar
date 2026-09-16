rule TrojanDownloader_O97M_Obfuse_JJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } 		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } 		$a_03_2 = {4f 70 65 6e 20 [0-15] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } 		$a_01_3 = {2e 43 61 70 74 69 6f 6e } 		$a_01_4 = {22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}