rule TrojanDownloader_O97M_Obfuse_JH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6f 77 2e 6c 79 2f 51 6f 48 62 4a } 		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 41 64 6f 62 65 52 65 61 64 65 72 2e 62 61 74 } 		$a_01_2 = {53 68 65 6c 6c 28 73 74 72 53 61 76 65 54 6f 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } 		$a_01_3 = {6f 62 6a 46 53 4f 2e 44 65 6c 65 74 65 46 69 6c 65 20 28 73 74 72 53 61 76 65 54 6f 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}