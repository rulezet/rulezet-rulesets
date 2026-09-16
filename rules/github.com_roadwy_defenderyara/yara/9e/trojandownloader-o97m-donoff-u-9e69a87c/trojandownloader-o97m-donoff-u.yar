rule TrojanDownloader_O97M_Donoff_U{
	meta:
		description = "TrojanDownloader:O97M/Donoff.U,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 4c 65 66 74 28 53 74 72 43 6f 6e 76 28 } 		$a_00_1 = {2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 55 42 6f 75 6e 64 28 } 		$a_00_2 = {48 43 41 4b 53 42 43 32 50 49 55 56 43 42 32 50 49 33 47 49 4c 55 48 47 43 49 55 47 55 59 4f 32 46 33 55 43 32 55 59 33 46 4f 32 33 4f 55 59 43 46 33 32 4f 59 55 44 48 4f 59 47 55 33 32 46 56 59 55 4f 32 33 47 46 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}