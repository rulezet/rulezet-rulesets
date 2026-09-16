rule TrojanDownloader_O97M_Donoff_74{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 68 74 42 74 51 70 6a 3a 52 38 2f 6a 2f 6d 52 38 61 6e 42 6e 52 51 61 52 2d 52 61 63 6a 52 74 7a 69 76 51 38 65 52 77 38 65 61 6a 72 38 2e 51 51 63 38 6f 6d 51 2f 52 42 73 79 7a 52 73 52 74 6a 65 6d 51 2f 38 42 63 61 6a 52 63 51 68 42 65 7a 2f 75 38 70 42 64 51 61 38 6a 74 65 6a 42 2e 65 38 42 78 7a 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}