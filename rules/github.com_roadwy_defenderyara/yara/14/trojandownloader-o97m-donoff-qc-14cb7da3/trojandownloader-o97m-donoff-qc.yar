rule TrojanDownloader_O97M_Donoff_QC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 } 		$a_01_1 = {3d 20 53 68 65 6c 6c 28 22 77 73 63 72 22 20 26 20 22 69 70 74 20 22 20 26 } 		$a_01_2 = {2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 31 30 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}