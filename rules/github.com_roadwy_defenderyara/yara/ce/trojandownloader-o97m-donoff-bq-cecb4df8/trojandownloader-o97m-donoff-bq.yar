rule TrojanDownloader_O97M_Donoff_BQ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 63 65 72 74 75 74 69 6c 2e 65 78 65 22 2c 20 22 2d 64 65 63 6f 64 65 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}