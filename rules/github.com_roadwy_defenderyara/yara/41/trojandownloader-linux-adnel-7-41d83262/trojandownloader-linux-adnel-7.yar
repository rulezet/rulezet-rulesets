rule TrojanDownloader_Linux_Adnel_7{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 43 79 6c 45 6b 77 4c 53 35 55 74 53 4f 20 3d 20 48 56 45 4b 37 6b 4d 30 51 57 76 28 4b 4a 39 4e 51 44 58 45 31 36 39 47 6b 43 73 68 2c 20 4c 58 38 70 30 29 } 		$a_01_1 = {53 68 65 6c 6c 20 46 43 79 6c 45 6b 77 4c 53 35 55 74 53 4f 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}