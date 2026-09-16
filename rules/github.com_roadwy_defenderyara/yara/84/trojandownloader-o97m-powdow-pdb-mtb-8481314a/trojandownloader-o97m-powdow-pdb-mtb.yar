rule TrojanDownloader_O97M_Powdow_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } 		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_2 = {49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 78 64 79 61 37 6a 36 27 2c 27 70 64 2e 62 61 74 27 29 } 		$a_01_3 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 33 70 76 34 71 74 27 2c 27 70 64 2e 62 61 74 27 29 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}