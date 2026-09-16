rule TrojanDownloader_O97M_Powdow_RVBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 77 77 2b 73 2b 63 2b 72 2b 69 2b 70 2b 74 2b 64 64 2b 73 2b 68 2b 65 2b 6c 2b 6c 29 2e 72 75 6e 73 74 72 65 6e 64 73 75 62 } 		$a_01_1 = {70 3d 22 70 22 6f 3d 22 6f 22 77 3d 22 77 22 65 3d 22 65 22 72 3d 22 72 22 73 3d 22 73 22 68 3d 22 68 22 6c 3d 22 6c 22 64 64 3d 22 2e 22 } 		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 29 6c 6f 76 65 65 6e 64 73 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}