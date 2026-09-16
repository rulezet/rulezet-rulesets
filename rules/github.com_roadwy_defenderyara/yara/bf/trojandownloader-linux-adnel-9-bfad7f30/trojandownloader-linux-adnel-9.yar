rule TrojanDownloader_Linux_Adnel_9{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 72 6f 2f 63 67 69 2d 62 69 6e 2f 77 65 64 2f 31 } 		$a_01_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e } 		$a_01_2 = {54 65 6d 70 } 		$a_01_3 = {53 68 65 6c 6c } 		$a_01_4 = {45 6e 76 69 72 6f 6e } 		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}