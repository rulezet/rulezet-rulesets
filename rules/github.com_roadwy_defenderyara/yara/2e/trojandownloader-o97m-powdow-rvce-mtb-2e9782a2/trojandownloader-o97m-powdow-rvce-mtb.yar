rule TrojanDownloader_O97M_Powdow_RVCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 6d 61 63 72 6f 28 29 64 69 6d 6d 79 75 72 6c 61 73 73 74 72 69 6e 67 6d 79 75 72 6c 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 69 65 6c 64 77 69 73 65 2e 6f 6e 6c 69 6e 65 2f 75 70 64 61 74 65 63 68 65 63 6b 2e 65 78 65 22 } 		$a_01_1 = {6f 73 74 72 65 61 6d 2e 63 6c 6f 73 65 65 6e 64 69 66 70 61 74 68 3d 22 75 70 64 61 74 65 63 68 65 63 6b 2e 65 78 65 22 73 68 65 6c 6c 70 61 74 68 2c 76 62 68 69 64 65 65 6e 64 73 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}