rule TrojanDownloader_O97M_Bartallex_E{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 41 52 54 20 2b 20 43 68 72 28 33 33 20 2b 20 31 29 } 		$a_00_1 = {4b 69 6c 6c 20 4d 59 5f 46 49 4c 45 4e 44 49 52 } 		$a_00_2 = {43 68 72 28 33 34 29 20 2b 20 22 34 2e 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2b 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 78 65 22 20 2b 20 43 68 72 28 33 34 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}