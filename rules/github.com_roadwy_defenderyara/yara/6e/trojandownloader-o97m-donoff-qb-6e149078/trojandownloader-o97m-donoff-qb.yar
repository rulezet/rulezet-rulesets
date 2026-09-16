rule TrojanDownloader_O97M_Donoff_QB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 62 69 6e 22 20 26 20 22 2e 62 61 22 20 26 20 22 73 65 36 34 22 } 		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 2e 41 64 6f 62 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}