rule TrojanDownloader_O97M_Donoff_75{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 53 75 62 20 [0-10] 28 42 79 56 61 6c 20 [0-10] 20 41 73 20 53 74 72 69 6e 67 29 [0-04] 53 65 74 20 [0-10] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 28 22 [0-40] 22 2c 20 22 [0-40] 22 29 29 [0-40] 2e 52 75 6e 20 [0-20] 2c 20 [0-08] 45 6e 64 20 53 75 62 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}