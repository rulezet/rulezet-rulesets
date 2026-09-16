rule TrojanDownloader_O97M_Tnega_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 } 		$a_01_1 = {3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 22 20 2b 20 22 73 63 72 69 70 74 22 20 2b 20 22 2e 65 78 65 20 22 } 		$a_01_2 = {22 57 53 63 72 69 70 74 2e 22 20 2b 20 22 53 68 65 22 20 2b 20 22 6c 6c 22 } 		$a_03_3 = {2b 20 22 2e 22 20 2b 20 22 76 22 0d 0a [0-05] 20 3d 20 90 1b 00 20 2b 20 22 62 73 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}