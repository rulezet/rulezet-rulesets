rule TrojanDownloader_O97M_Donoff_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 6b 77 77 73 3d 32 32 3c 34 31 35 35 3c 31 3a 3c 31 35 36 34 3d 3b 33 3b 33 32 34 35 36 36 36 31 68 7b 68 22 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}