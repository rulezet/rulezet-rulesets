rule TrojanDownloader_Linux_Adnel_5{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 41 55 72 52 58 78 31 63 32 45 6e 64 6f 20 3d 20 59 75 65 4d 5a 41 62 6c 4a 47 28 4d 57 6b 33 7a 41 2c 20 42 5a 62 35 59 4c 61 56 54 4f 62 30 29 } 		$a_01_1 = {53 68 65 6c 6c 20 47 41 55 72 52 58 78 31 63 32 45 6e 64 6f 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}