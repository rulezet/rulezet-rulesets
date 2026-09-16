rule TrojanDownloader_O97M_Powdow_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 72 6d 2e 64 6f 77 6e 6c 6f 61 64 20 [0-02] 2c 20 22 63 32 2e 70 64 66 22 } 		$a_01_1 = {53 68 65 6c 6c 20 77 75 20 26 20 62 6e 20 26 20 22 33 32 20 63 32 2e 70 64 66 22 } 		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } 		$a_01_3 = {2e 53 65 6c 65 63 74 4e 6f 64 65 73 28 22 2f 2f 49 74 65 6d 73 22 29 28 31 29 2e 43 68 69 6c 64 4e 6f 64 65 73 28 32 29 2e 54 65 78 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}