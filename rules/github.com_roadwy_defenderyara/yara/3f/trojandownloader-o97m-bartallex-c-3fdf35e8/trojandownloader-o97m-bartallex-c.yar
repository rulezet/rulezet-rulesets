rule TrojanDownloader_O97M_Bartallex_C{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 6e 2e 63 6f 6d 2f 72 61 77 2e 70 68 70 3f 69 3d } 		$a_00_1 = {2f 75 73 2f 66 69 6c 65 22 20 2b 20 53 58 45 } 		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}