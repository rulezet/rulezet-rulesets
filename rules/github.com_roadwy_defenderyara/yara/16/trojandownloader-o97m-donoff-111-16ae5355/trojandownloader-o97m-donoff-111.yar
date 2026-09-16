rule TrojanDownloader_O97M_Donoff_111{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 31 36 36 34 a8 31 38 35 36 a8 31 38 35 36 a8 31 37 39 32 a8 39 32 38 a8 37 35 32 a8 37 35 32 a8 31 38 34 30 a8 31 38 35 36 a8 31 36 31 36 a8 31 36 31 36 a8 31 37 32 38 a8 31 36 33 32 a8 31 38 34 30 a8 37 33 36 a8 31 35 38 34 a8 31 37 37 36 a8 31 37 34 34 a8 37 33 36 a8 31 37 34 34 a8 31 39 32 30 a8 37 35 32 a8 38 39 36 a8 39 31 32 a8 31 39 33 36 a8 31 36 34 38 a8 38 36 34 a8 38 38 30 a8 31 37 36 30 a8 31 37 37 36 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}