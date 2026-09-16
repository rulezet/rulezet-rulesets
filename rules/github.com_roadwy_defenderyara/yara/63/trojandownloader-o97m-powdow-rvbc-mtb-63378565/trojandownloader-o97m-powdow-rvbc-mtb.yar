rule TrojanDownloader_O97M_Powdow_RVBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 2e 41 64 64 20 22 61 6b 73 6a 64 6c 61 6b 73 6a 64 71 6f 77 69 6a 64 65 6e 65 77 63 22 } 		$a_01_1 = {22 68 74 22 0d 0a 6f 62 6a 2e 41 64 64 20 22 74 70 73 22 } 		$a_01_2 = {4d 69 64 24 28 73 74 72 54 65 78 74 2c 20 31 2c 20 6c 6e 67 55 73 65 64 29 } 		$a_01_3 = {6f 6e 65 73 65 73 65 73 65 20 3d 20 6f 62 6a 2e 47 65 74 53 74 72 } 		$a_01_4 = {43 61 6c 6c 20 41 4c 4b 53 4a 44 4b 4c 41 53 4a 44 4c 4b 41 4a 53 44 4c 4b 41 4a 53 44 4b 4c 4a 41 53 4c 4b 44 4a 4c 4b 41 53 4b 4c 41 53 4e 43 4d 4c 53 41 4e 43 4d 41 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}