rule TrojanDownloader_O97M_Donoff_BO{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BO,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 69 64 28 73 68 65 6c 6c 43 6f 64 65 2c } 		$a_00_1 = {72 4c 2c 20 7a 4c 2c 20 26 48 35 30 30 30 2c 20 26 48 31 30 30 30 2c 20 26 48 34 30 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}