rule TrojanDownloader_O97M_Donoff_MXI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5e 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } 		$a_01_1 = {24 74 3d 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 53 74 72 69 6e 67 28 24 4d 6f 29 7c 49 45 58 } 		$a_03_2 = {6d 69 7a 20 3d 20 52 65 70 6c 61 63 65 28 [0-10] 2c 20 22 5e 22 2c 20 22 50 22 29 } 		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 37 32 22 20 26 20 4d 4d 4d 29 } 		$a_01_4 = {52 75 6e 20 73 20 26 20 6d 69 7a 2c 20 53 69 6e 28 30 2e 31 29 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}