rule TrojanDownloader_O97M_Dridex_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 61 67 65 6e 74 6f 32 2e 74 68 65 62 72 61 6e 64 72 65 70 75 62 6c 69 63 2e 73 74 6f 72 65 2f 73 65 74 75 70 2f 70 75 62 2f 66 6f 6e 74 73 2f 6f 70 65 6e 73 61 6e 73 2f 62 6f 6c 64 2f 49 33 36 49 4d 49 55 74 49 2e 70 68 70 } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 63 6f 6f 6b 69 6e 67 73 63 68 6f 6f 6c 61 6c 6f 76 65 73 74 6f 72 79 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 32 30 2f 30 38 2f 4d 4a 7a 7a 57 4d 54 4e 30 71 35 33 2e 70 68 70 } 		$a_01_2 = {68 74 74 70 73 3a 2f 2f 67 65 74 69 74 73 6f 6c 75 74 69 6f 6e 73 2e 69 6e 2f 6c 69 62 2f 62 6f 6f 74 73 74 72 61 70 2f 63 73 73 2f 39 64 64 6a 62 37 49 5a 46 48 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}