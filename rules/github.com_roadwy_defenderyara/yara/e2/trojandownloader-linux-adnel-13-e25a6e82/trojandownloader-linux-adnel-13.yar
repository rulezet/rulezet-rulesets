rule TrojanDownloader_Linux_Adnel_13{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 48 67 4f 52 79 6c 75 77 51 32 53 5a 61 37 28 44 48 47 6e 32 77 36 67 6c 45 39 38 70 29 20 3d 20 58 73 72 28 55 70 38 6f 41 4c 69 70 69 49 4a 29 } 		$a_01_1 = {49 58 4c 49 4c 69 52 6a 49 20 3d 20 4b 45 5a 71 6b 71 4f 6a 52 33 4a 66 64 70 4b 49 28 52 5a 69 50 72 41 45 34 2c 20 51 48 67 4f 52 79 6c 75 77 51 32 53 5a 61 37 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}