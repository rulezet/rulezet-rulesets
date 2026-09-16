rule TrojanDownloader_O97M_Donoff_96{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 35 30 2e 30 29 20 47 65 63 6b 6f 2f 32 30 32 30 30 31 30 32 20 46 69 72 65 66 6f 78 2f 35 30 2e 30 } 		$a_01_1 = {41 72 72 61 79 28 22 41 22 2c 20 22 42 22 2c 20 22 43 22 2c 20 22 44 22 2c 20 22 45 22 2c 20 22 46 22 2c 20 22 47 22 2c 20 22 48 22 2c 20 22 49 22 2c 20 22 4a 22 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}