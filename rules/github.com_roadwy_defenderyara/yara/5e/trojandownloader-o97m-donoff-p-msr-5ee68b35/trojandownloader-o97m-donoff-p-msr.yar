rule TrojanDownloader_O97M_Donoff_P_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.P!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6f 72 61 74 6f 72 69 6f 73 74 73 75 72 75 6b 79 6f 2e 63 6f 6d 2e 62 72 2f 61 72 71 75 69 76 6f 73 2f 74 65 73 74 65 2e 68 74 61 } 		$a_00_1 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } 		$a_00_2 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}