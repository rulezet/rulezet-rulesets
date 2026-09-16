rule TrojanDownloader_O97M_Donoff_37{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 65 2e 74 74 2f 61 70 69 2f 31 2f 66 69 6c 65 73 2f 34 70 36 45 43 4a 43 32 2f 30 2f 62 6c 6f 62 3f 64 6f 77 6e 6c 6f 61 64 } 		$a_01_1 = {68 6d 6d 6d 2e 45 58 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}