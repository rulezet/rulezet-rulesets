rule TrojanDownloader_O97M_Donoff_57{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 28 22 6f 4e 70 54 30 69 20 74 69 30 6c 2e 62 65 20 2f 3b 65 74 69 2e 57 20 36 64 20 57 53 30 77 63 34 45 4d 20 6d 20 31 7a 54 61 72 2e 6c 36 69 64 3b 61 31 6c 6e 57 35 20 3b 2f 6e 30 4f 4d 2e 6f 28 36 49 29 73 6f 3b 20 22 2c 20 33 38 38 2c 20 37 34 38 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}