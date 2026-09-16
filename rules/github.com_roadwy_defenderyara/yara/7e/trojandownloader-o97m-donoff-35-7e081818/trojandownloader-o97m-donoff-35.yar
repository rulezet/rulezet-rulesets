rule TrojanDownloader_O97M_Donoff_35{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 27 68 74 22 20 2b 20 22 74 70 73 3a 2f 22 20 2b 20 22 2f 74 76 61 22 20 2b 20 22 76 69 2e 77 69 22 20 2b 20 22 6e 2f 70 61 67 22 20 2b 20 22 6f 2e 65 78 22 20 2b 20 22 65 27 2b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}