rule TrojanDownloader_Linux_Adnel_4{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 58 75 34 41 75 59 66 6d 20 3d 20 55 6b 6b 32 58 28 50 4e 4c 4f 73 45 6a 69 63 53 38 76 6c 56 6d 77 36 2c 20 4b 76 6b 7a 72 4e 68 63 73 77 79 38 29 } 		$a_01_1 = {53 68 65 6c 6c 20 4c 58 75 34 41 75 59 66 6d 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}