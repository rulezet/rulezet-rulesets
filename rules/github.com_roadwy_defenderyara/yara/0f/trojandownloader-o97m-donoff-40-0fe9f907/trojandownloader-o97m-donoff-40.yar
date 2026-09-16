rule TrojanDownloader_O97M_Donoff_40{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 63 4d 67 66 61 73 6b 44 2e 67 66 61 73 6b 65 78 67 66 61 73 6b 65 20 67 66 61 73 6b 2f 43 67 66 61 73 6b } 		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-08] 2c 20 76 62 48 69 64 65 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}