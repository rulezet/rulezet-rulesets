rule TrojanDownloader_Linux_Donoff_7{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 70 75 74 65 72 20 3d 20 41 72 72 61 79 28 } 		$a_03_1 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 [0-04] 20 2b 20 69 29 } 		$a_00_2 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 63 6f 6d 70 75 74 65 72 29 2c 20 46 61 6c 73 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}