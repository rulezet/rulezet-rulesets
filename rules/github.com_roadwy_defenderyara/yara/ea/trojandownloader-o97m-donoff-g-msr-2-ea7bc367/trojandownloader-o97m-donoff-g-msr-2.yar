rule TrojanDownloader_O97M_Donoff_G_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6b 61 70 69 73 6b 61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 22 20 26 20 22 70 22 29 } 		$a_03_1 = {70 6f 70 33 72 2e 52 75 6e 20 73 6b 61 70 69 73 6b 61 20 26 20 [0-09] 2e 54 61 67 2c 20 30 2c 20 46 61 6c 73 65 } 		$a_03_2 = {46 69 6c 65 43 6f 70 79 20 [0-09] 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 6b 61 70 69 73 6b 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}