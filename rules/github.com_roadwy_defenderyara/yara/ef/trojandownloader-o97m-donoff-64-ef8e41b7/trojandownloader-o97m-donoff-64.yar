rule TrojanDownloader_O97M_Donoff_64{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 50 6f 77 65 72 53 22 [0-10] 3d 20 22 68 65 6c 6c 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 2d 4e 6f 4c 20 2d 57 69 6e 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 } 		$a_02_1 = {53 68 65 6c 6c 20 [0-10] 45 6e 64 20 53 75 62 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}