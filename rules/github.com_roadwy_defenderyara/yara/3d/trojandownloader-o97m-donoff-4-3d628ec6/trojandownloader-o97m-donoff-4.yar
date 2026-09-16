rule TrojanDownloader_O97M_Donoff_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 78 78 78 2d 36 43 48 7f 6f 1a 07 77 7a 19 07 7e 79 19 02 76 70 03 19 01 21 43 57 6b 25 4f 53 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}