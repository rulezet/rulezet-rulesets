rule TrojanDownloader_Linux_Adnel_15{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 74 75 6b 61 6e 67 65 63 75 70 72 75 73 2e 63 6f 6d 2f 63 72 5f 66 69 6c 65 5f 69 6e 73 74 2e 65 78 65 22 } 		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 22 2c 20 22 22 20 20 27 28 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}