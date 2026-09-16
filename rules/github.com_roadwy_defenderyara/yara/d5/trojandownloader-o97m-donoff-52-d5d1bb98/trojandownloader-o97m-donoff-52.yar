rule TrojanDownloader_O97M_Donoff_52{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 69 6d 72 79 70 74 28 22 65 6e 26 37 67 30 36 6c 3e 3c 71 6b 2d 23 24 66 76 3d 6c 71 6a 6e 32 7e 71 65 77 31 3c 7e 7e 67 6a 6e 70 6d 30 7f 24 2b 6c 22 29 20 26 20 53 69 6d 72 79 70 74 28 22 63 7b 31 2f 73 7a 61 7e 76 2f 33 32 6e 22 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}