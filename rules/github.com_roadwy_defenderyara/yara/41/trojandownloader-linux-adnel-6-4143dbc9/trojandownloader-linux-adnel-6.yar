rule TrojanDownloader_Linux_Adnel_6{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 64 55 69 20 3d 20 50 30 49 46 4f 6a 4c 6a 4c 47 55 6e 58 28 48 62 36 47 6c 49 30 4b 67 62 33 59 48 29 } 		$a_01_1 = {4b 36 32 33 6e 62 59 69 6e 62 20 3d 20 44 64 55 69 28 58 67 64 49 42 54 2c 20 4c 67 42 4c 6a 39 73 75 66 44 6c 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}