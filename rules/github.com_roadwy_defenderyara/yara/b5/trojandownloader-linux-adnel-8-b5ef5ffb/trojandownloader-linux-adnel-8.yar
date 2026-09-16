rule TrojanDownloader_Linux_Adnel_8{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 41 6d 42 30 4d 79 5a 37 49 76 47 56 43 20 3d 20 49 34 77 50 43 70 4e 69 4d 59 31 36 28 53 36 6c 46 4a 45 6d 44 2c 20 58 73 56 66 75 57 61 62 32 67 64 32 42 37 29 } 		$a_01_1 = {53 68 65 6c 6c 20 47 41 6d 42 30 4d 79 5a 37 49 76 47 56 43 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}