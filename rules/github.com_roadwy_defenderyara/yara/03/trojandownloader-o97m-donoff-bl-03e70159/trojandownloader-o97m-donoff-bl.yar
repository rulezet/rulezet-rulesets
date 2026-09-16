rule TrojanDownloader_O97M_Donoff_BL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BL,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 4f 4c 77 38 6f 4f 77 43 55 6f 35 6b 2c 20 49 71 6e 54 66 30 6d 33 72 34 56 6b 56 2c 20 34 2c 20 57 34 4b 66 65 74 74 41 32 59 7a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}