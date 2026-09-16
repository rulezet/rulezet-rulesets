rule TrojanDownloader_O97M_Donoff_117{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 6f 6c 6f 76 20 3d 20 41 72 72 61 79 28 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c } 		$a_03_1 = {2e 4f 70 65 6e 20 22 47 22 20 2b 20 55 43 61 73 65 28 [0-10] 29 20 2b 20 22 54 22 2c 20 52 65 64 69 73 74 72 69 62 75 74 65 28 73 6f 6c 6f 76 2c 20 90 05 02 03 30 2d 39 29 2c 20 46 61 6c 73 65 [0-05] 6a 73 6f 6e 50 61 72 73 65 53 74 72 69 6e 67 2e 53 65 6e 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}