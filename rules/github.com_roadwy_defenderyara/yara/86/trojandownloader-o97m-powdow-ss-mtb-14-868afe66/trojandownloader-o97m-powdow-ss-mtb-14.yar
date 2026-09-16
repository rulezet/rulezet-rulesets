rule TrojanDownloader_O97M_Powdow_SS_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 20 3d 20 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 71 6d 67 56 69 61 31 5a } 		$a_01_1 = {52 65 73 75 6c 74 61 64 6f 20 3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 6d 73 68 74 61 2e 65 78 65 20 22 20 26 20 63 6f 6d 2c 20 30 29 } 		$a_01_2 = {55 73 65 72 46 6f 72 6d 31 2e 57 65 62 42 72 6f 77 73 65 72 31 2e 4e 61 76 69 67 61 74 65 20 28 22 61 62 6f 75 74 3a 62 6c 61 6e 6b 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}