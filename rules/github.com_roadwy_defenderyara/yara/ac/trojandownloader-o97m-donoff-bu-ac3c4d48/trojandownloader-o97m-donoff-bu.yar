rule TrojanDownloader_O97M_Donoff_BU{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BU,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 73 63 28 22 30 22 29 20 54 6f 20 41 73 63 28 22 39 22 29 3a } 		$a_03_1 = {4c 6f 6f 70 [0-05] 90 11 10 00 90 12 1f 00 20 3d 20 22 5c 66 69 69 75 64 66 38 33 2e 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}