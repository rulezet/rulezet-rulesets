rule TrojanDownloader_Linux_Bartallex_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 		$a_01_1 = {26 20 22 2e 22 20 26 20 22 65 22 20 26 20 22 78 22 20 26 20 22 65 22 } 		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 61 22 20 26 20 22 70 22 20 26 20 22 70 22 20 26 20 22 64 22 20 26 20 22 61 22 20 26 20 22 74 22 20 26 20 22 61 22 29 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}