rule TrojanDownloader_O97M_Powdow_RVBW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 5f 73 68 65 6c 6c 40 5f 28 78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62 } 		$a_01_1 = {78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 5f 3d 6e 6f 74 65 70 61 64 2e 6e 6f 74 65 70 61 64 2e 76 61 6c 75 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 5f 2e 5f 70 72 69 6e 74 } 		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}