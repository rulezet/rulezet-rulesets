rule TrojanDownloader_O97M_TrickBot_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 42 7c 6a 7c 76 7c 44 7c 71 7c 50 7c 58 7c 4d 7c 7a 7c 4c 7c 55 7c 5a 7c 46 7c 77 7c 56 7c 4e 7c 51 7c 4b 7c 49 7c 47 7c 48 7c 59 22 } 		$a_01_1 = {50 75 47 76 56 20 3d 20 77 75 62 48 35 6f 2e 52 65 70 6c 61 63 65 28 4b 66 30 56 34 49 34 37 36 28 30 29 2c 20 22 22 29 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}