rule TrojanDownloader_O97M_Donoff_EY_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {47 76 63 4d 69 6a 73 20 3d 20 53 62 74 68 77 56 49 44 69 6e 46 20 2b 20 49 54 63 6b 6e 4e 4e 76 58 59 0d 0a 56 42 41 2e 53 68 65 6c 6c 24 20 47 76 63 4d 69 6a 73 2c 20 30 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 77 4c 62 46 43 43 50 49 69 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}