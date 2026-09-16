rule TrojanDownloader_O97M_Powdow_RVCB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 68 65 6c 6c 2e 72 75 6e 22 63 6d 64 2f 63 22 26 73 61 76 65 70 61 74 68 26 22 3e 6e 75 6c 32 3e 26 31 22 2c 30 2c 74 72 75 65 65 6e 64 73 75 62 } 		$a_01_1 = {75 72 6c 3d 22 68 74 74 70 73 3a 2f 2f 6c 6c 6f 79 64 66 65 64 64 65 72 2e 63 6f 6d 2f 73 69 32 6f 72 2e 62 61 74 22 27 64 6f 77 6e 6c 6f 61 64 74 68 65 66 69 6c 65 } 		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}