rule TrojanDownloader_O97M_Donoff_81{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 22 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 2b 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 } 		$a_03_1 = {22 73 22 20 2b 20 90 11 05 00 [0-15] 20 2b 20 22 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}