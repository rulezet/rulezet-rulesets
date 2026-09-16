rule TrojanDownloader_Linux_Adnel_16{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 47 69 45 51 66 20 3d 20 43 68 72 24 28 56 61 6c 28 43 68 72 24 28 33 38 29 20 26 20 43 68 72 24 28 37 32 29 20 26 20 4d 69 64 24 28 6b 5a 74 6b 62 6f 7a 69 2c 20 54 51 6d 48 49 52 63 51 41 50 6a 43 2c 20 32 29 29 29 } 		$a_00_1 = {65 50 55 75 69 67 61 73 70 4c 69 47 4c 20 3d 20 65 50 55 75 69 67 61 73 70 4c 69 47 4c 20 26 20 55 47 69 45 51 66 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}