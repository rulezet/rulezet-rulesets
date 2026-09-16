rule TrojanDownloader_O97M_Powdow_RVCD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 74 72 63 6f 6d 6d 61 6e 64 3d 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 63 22 22 65 78 70 6c 6f 72 65 72 27 5c 5c 38 39 2e 32 33 2e 39 38 2e 32 32 5c 6c 6e 5c 27 3b 73 74 61 72 74 2d 73 6c 65 65 70 2d 73 65 63 6f 6e 64 73 31 3b 73 74 6f 70 2d 70 72 6f 63 65 73 73 2d 6e 61 6d 65 65 78 70 6c 6f 72 65 72 3b 5c 5c 38 39 2e 32 33 2e 39 38 2e 32 32 5c 6c 6e 5c 6b 6f 6e 73 74 61 6e 74 69 6e 2e 65 78 65 } 		$a_01_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}