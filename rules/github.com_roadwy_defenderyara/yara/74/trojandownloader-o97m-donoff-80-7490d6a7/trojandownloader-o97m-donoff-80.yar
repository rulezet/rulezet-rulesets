rule TrojanDownloader_O97M_Donoff_80{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 [0-20] 46 75 6e 63 74 69 6f 6e 20 [0-20] 28 29 [0-04] 44 69 6d 20 [0-50] 20 3d 20 [0-10] 2e [0-10] 2e 54 65 78 74 [0-04] 53 68 65 6c 6c 20 28 [0-10] 2e [0-10] 2e 54 65 78 74 20 26 20 [0-30] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}