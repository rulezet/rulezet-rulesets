rule TrojanDownloader_Linux_Adnel_18{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 66 61 43 37 34 55 36 38 73 63 53 35 71 79 20 3d 20 5a 52 35 42 63 30 35 72 73 41 67 31 5a 41 58 2e 53 39 39 52 79 71 4c 6b 28 65 66 61 43 37 34 55 36 38 73 63 53 35 71 79 2c 20 6e 4e 66 4a 39 71 42 41 44 69 47 50 5a 68 2c 20 64 77 77 47 51 70 41 31 4a 36 30 76 4e 4b 45 29 } 		$a_03_1 = {2e 53 39 39 52 79 71 4c 6b 28 [0-18] 2c 20 [0-18] 2c 20 64 77 77 47 51 70 41 31 4a 36 30 76 4e 4b 45 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}