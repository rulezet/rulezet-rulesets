rule TrojanDownloader_Linux_Adnel_14{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 22 69 3f 70 68 70 2e 64 61 6f 6c 6e 77 6f 64 2f 6d 6f 63 2e 6e 69 62 65 74 73 61 70 2f 2f 3a 70 } 		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 74 52 61 67 45 37 4d 4b 3d 22 29 } 		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 77 77 77 77 77 77 77 57 57 57 65 66 73 2e 76 62 73 22 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}