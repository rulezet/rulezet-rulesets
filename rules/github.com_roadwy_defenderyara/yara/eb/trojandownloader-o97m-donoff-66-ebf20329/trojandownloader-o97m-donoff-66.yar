rule TrojanDownloader_O97M_Donoff_66{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 43 6d [0-08] 64 2e [0-08] 45 78 [0-08] 65 20 [0-08] 2f 43 [0-08] 20 22 22 [0-08] 70 4f [0-08] 57 65 [0-08] 72 53 [0-08] 68 65 [0-08] 4c 6c [0-08] 2e 65 [0-08] 58 45 } 		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-10] 2c 20 [0-08] 29 } 	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}