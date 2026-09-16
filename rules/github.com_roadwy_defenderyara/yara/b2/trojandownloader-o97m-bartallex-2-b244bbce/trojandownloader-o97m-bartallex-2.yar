rule TrojanDownloader_O97M_Bartallex_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 67 67 63 3a 2f 2f 6e 79 68 70 6e 65 71 62 61 6e 2e 70 62 7a 2f 77 66 2f 6f 76 61 2e 72 6b 72 } 		$a_01_1 = {5c 71 66 55 55 55 2e 72 6b 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}