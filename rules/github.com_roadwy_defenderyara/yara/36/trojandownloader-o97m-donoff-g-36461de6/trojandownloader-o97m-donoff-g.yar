rule TrojanDownloader_O97M_Donoff_G{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-15] 29 20 26 20 22 2f 74 73 78 33 22 20 2b 20 } 		$a_01_1 = {3d 20 35 20 54 6f 20 4e 6c 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4e 65 78 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}