rule TrojanDownloader_O97M_Donoff_12{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {79 6f 73 2f 6d 74 63 70 70 2e 69 2e 74 69 77 63 64 74 6f 77 2f 6e 68 65 77 31 69 65 67 2f 2e 6d 6d 2f 2f 32 78 2f 6d 3a 76 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}