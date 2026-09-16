rule TrojanDownloader_O97M_Donoff_25{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 2b 20 22 74 6f 70 2f 68 74 74 70 64 2f 22 } 		$a_03_1 = {3d 20 22 74 22 20 2b 20 22 74 22 [0-15] 20 3d 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}