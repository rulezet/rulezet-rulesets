rule TrojanDownloader_Linux_Donoff_3{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 32 38 30 2f 34 36 61 75 2e 65 78 65 } 		$a_01_1 = {22 54 4d 50 22 29 20 26 20 22 5c 4c 57 47 4b 41 49 2e 65 78 65 } 		$a_01_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 41 75 74 6f 5f 4f 70 65 6e 0d 0a 45 6e 64 20 53 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}