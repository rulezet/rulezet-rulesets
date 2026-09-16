rule TrojanDownloader_O97M_Donoff_FD{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 2e 44 65 63 6f 64 65 64 54 65 78 74 2c 20 73 69 20 2d 20 32 34 30 30 20 2d 20 31 36 } 		$a_01_1 = {54 68 65 6e 20 53 68 65 6c 6c 20 50 6f 77 5f 53 53 53 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}