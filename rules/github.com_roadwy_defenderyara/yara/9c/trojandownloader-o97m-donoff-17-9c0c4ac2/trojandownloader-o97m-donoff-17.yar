rule TrojanDownloader_O97M_Donoff_17{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 42 37 64 20 3d 20 28 53 6f 58 72 20 41 6e 64 20 4e 6f 74 20 51 51 4b 29 20 4f 72 20 28 4e 6f 74 20 53 6f 58 72 20 41 6e 64 20 51 51 4b 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}