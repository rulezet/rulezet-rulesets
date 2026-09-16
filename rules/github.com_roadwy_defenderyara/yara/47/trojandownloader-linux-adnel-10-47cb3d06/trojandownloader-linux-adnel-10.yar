rule TrojanDownloader_Linux_Adnel_10{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 2e 70 6f 6d 66 2e 73 65 2f } 		$a_01_1 = {2f 64 77 6e 6c 76 68 22 } 		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 73 74 61 72 74 75 70 2e 65 78 65 22 } 		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 30 2c 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}