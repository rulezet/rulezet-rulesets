rule TrojanDownloader_O97M_Donoff_84{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 76 67 4e 50 6b 4d 52 66 70 4b 58 4c 78 59 76 75 56 44 55 47 4b 6c 4c 57 28 22 66 79 66 2f 6f 6f 70 30 6f 66 30 63 68 30 75 66 6f 2f 75 66 6f 73 70 73 6c 30 30 3b 71 75 75 69 22 29 } 		$a_01_1 = {43 76 67 4e 50 6b 4d 52 66 70 4b 58 4c 78 59 76 75 56 44 55 47 4b 6c 4c 57 28 22 66 79 66 2f 74 7a 74 75 74 70 69 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}