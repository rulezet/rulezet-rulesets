rule TrojanDownloader_O97M_Donoff_FD_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 } 		$a_03_1 = {68 74 74 70 73 3a 2f 2f 6d 73 6f 66 66 69 63 65 2e 68 6f 73 74 2f ?? ?? ?? 68 6f 73 74 2e 65 78 65 22 2c 20 70 61 74 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}