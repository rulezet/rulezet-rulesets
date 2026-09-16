rule TrojanDownloader_O97M_Donoff_51{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 45 34 43 33 43 31 46 46 38 31 38 32 35 41 35 35 30 38 32 37 33 39 33 44 31 33 33 32 32 38 31 38 36 41 32 35 32 44 33 37 36 46 35 35 31 36 34 41 34 33 31 30 33 30 22 29 2c 20 22 57 50 49 54 34 72 73 31 79 4d 52 44 70 4a 48 73 54 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}