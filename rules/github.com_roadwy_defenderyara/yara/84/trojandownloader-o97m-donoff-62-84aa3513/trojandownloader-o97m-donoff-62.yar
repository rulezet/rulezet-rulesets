rule TrojanDownloader_O97M_Donoff_62{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 69 67 68 74 28 22 63 6f 63 68 6c 65 61 72 69 75 73 77 69 22 2c 20 32 29 20 2b 20 4d 69 64 28 22 64 69 73 62 65 6e 63 68 6e 6d 67 6d 75 6e 64 65 72 65 73 74 69 6d 61 74 69 6f 6e 22 2c 20 39 2c 20 34 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 3a 73 74 22 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}