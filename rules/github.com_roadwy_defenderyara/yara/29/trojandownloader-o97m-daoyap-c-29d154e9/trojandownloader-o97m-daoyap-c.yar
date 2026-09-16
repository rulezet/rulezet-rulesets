rule TrojanDownloader_O97M_Daoyap_C{
	meta:
		description = "TrojanDownloader:O97M/Daoyap.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 2b 20 22 2e 22 20 2b 20 22 65 22 20 2b 20 22 78 22 20 2b 20 22 65 } 		$a_03_1 = {68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 22 20 2b 20 [0-08] 20 2b 20 22 45 54 22 } 		$a_01_2 = {74 65 6d 70 46 6f 6c 64 65 72 20 3d 20 70 72 6f 63 65 73 73 45 6e 76 28 22 54 45 4d 22 20 2b 20 22 50 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}