rule TrojanDownloader_O97M_Donoff_20{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 61 72 6b 62 72 65 61 6b 2e 77 65 62 63 69 6e 64 61 72 69 6f 2e 63 6f 6d 2f 75 70 64 61 74 65 2f 6d 79 61 70 70 2e 7a 69 70 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}