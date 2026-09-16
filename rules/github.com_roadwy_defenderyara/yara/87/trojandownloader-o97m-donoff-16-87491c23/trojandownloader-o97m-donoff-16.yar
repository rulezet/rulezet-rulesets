rule TrojanDownloader_O97M_Donoff_16{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 64 6f 6c 70 68 69 6e 32 30 30 30 2e 69 72 2f 74 6d 70 2f 22 } 		$a_01_1 = {22 67 6e 66 2e 6a 6f 74 70 65 65 2e 64 65 2f 74 6d 70 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}