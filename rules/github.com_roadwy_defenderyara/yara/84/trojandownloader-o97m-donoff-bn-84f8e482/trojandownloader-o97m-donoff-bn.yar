rule TrojanDownloader_O97M_Donoff_BN{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BN,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {22 4e 65 77 4d 61 63 72 6f 73 22 0d 0a 53 75 62 } 		$a_00_1 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}