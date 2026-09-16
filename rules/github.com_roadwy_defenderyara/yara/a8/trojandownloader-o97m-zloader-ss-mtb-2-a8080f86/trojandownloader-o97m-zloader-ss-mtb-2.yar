rule TrojanDownloader_O97M_Zloader_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Zloader.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 34 2e 34 31 2e 32 39 2f 6f 6f 69 } 		$a_01_1 = {77 79 2e 70 64 66 20 2d 4a 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 63 64 6e 75 70 64 61 74 65 } 		$a_01_2 = {72 75 6e 64 6c 6c 33 32 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 63 64 6e 75 70 64 61 74 65 72 61 70 69 2e 70 6e 67 } 		$a_01_3 = {43 55 56 50 51 52 42 41 58 57 47 50 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}