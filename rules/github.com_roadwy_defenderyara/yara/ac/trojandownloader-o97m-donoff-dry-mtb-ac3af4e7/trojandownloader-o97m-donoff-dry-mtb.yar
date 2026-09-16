rule TrojanDownloader_O97M_Donoff_DRY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 65 6e 20 73 69 73 74 65 72 73 20 77 76 } 		$a_03_1 = {34 30 37 2e 63 64 2e 67 6f 76 2e 6d 6e 2f 5f 57 35 34 73 45 6f 5a 4b 6c 2d 6d 32 77 36 52 5a 2e 70 68 70 3f 78 3d 4d 44 41 77 4d 53 44 71 75 46 6a 6e 6e 51 66 4e 73 6b 75 51 77 58 53 46 70 79 48 30 5a 39 90 0a 4b 00 68 74 74 70 3a 2f 2f } 		$a_01_2 = {79 76 2e 65 78 65 63 20 22 72 65 67 73 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 64 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}