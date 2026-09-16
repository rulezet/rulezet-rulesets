rule TrojanDownloader_O97M_Zloader_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Zloader.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a 63 6f 6d 74 65 63 68 2e 63 6f 6d 2f 72 6f 62 31 32 32 44 7a 6a 73 64 46 41 2e 64 6c 6c 20 2d 4a 20 2d 6f 20 63 } 		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 63 64 6e 75 70 } 		$a_01_2 = {52 49 5a 4a 5a 43 42 52 } 		$a_01_3 = {72 75 6e 64 6c 6c 33 32 20 63 3a 5c 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}