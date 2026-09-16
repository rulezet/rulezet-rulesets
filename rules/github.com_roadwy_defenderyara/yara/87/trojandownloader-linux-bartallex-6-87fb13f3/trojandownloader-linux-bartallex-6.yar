rule TrojanDownloader_Linux_Bartallex_6{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 54 54 48 20 3d 20 22 68 74 74 70 22 20 26 20 22 3a 2f 2f 22 } 		$a_01_1 = {42 51 48 4a 44 51 20 3d 20 22 73 61 22 20 2b 20 22 76 65 70 22 20 2b 20 22 69 63 22 20 26 20 43 68 72 28 34 36 29 20 26 20 22 73 75 22 20 2b 20 48 55 51 44 } 		$a_01_2 = {54 53 54 53 20 3d 20 22 2e 22 20 2b 20 22 74 78 22 20 2b 20 22 74 22 } 		$a_01_3 = {47 4e 47 20 3d 20 22 2e 6a 22 20 26 20 22 70 67 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}