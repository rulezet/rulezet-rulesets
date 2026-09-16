rule TrojanDownloader_O97M_Bartallex_8{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 53 66 4f 30 61 33 75 61 30 71 65 42 2c 20 30 } 		$a_01_1 = {53 66 4f 30 61 33 75 61 30 71 65 42 20 3d 20 53 66 4f 30 61 33 75 61 30 71 65 42 20 26 20 22 32 33 39 2c 32 34 30 2c 32 30 32 2c 32 32 36 2c 32 33 37 2c 32 30 32 2c 32 30 2c 32 30 2c 31 31 38 2c 36 31 2c 38 39 2c 36 34 2c 38 2c 31 32 33 2c 36 35 2c 35 37 2c 36 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}