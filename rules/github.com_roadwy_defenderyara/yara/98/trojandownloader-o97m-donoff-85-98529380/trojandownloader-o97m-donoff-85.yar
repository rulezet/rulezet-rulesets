rule TrojanDownloader_O97M_Donoff_85{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 44 6f 5e 22 20 26 20 22 77 6e 22 20 26 20 22 6c 6f 5e 61 64 22 20 26 20 22 46 69 22 20 26 20 22 5e 6c 65 28 27 68 74 22 20 26 20 22 5e 74 5e 70 } 		$a_01_1 = {48 65 61 5e 64 65 72 73 2e 41 64 5e 64 22 20 26 20 22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 22 20 26 20 22 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}