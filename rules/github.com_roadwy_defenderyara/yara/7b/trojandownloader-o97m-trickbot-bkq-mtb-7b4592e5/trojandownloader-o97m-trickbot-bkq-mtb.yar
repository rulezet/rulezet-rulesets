rule TrojanDownloader_O97M_TrickBot_BKQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BKQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 22 63 22 20 26 20 69 43 6f 6d 70 73 46 6f 72 20 26 20 68 74 6d 6c 46 75 6e 63 54 6f 29 } 		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 63 6f 72 65 54 6f 2c 20 74 6f 56 61 72 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29 } 		$a_01_2 = {62 71 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 63 6f 6d 70 73 43 6f 6d 70 73 43 6f 6d 70 73 2e 68 74 61 22 2c 20 22 6d 64 20 2f 63 20 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}