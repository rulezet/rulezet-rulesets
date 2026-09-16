rule TrojanDownloader_O97M_Powdow_SS_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 [0-03] 6f 62 6a 2e 6c 6f 6c [0-03] 45 6e 64 20 53 75 62 } 		$a_03_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6c 6f 6c 29 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 6c 6f 6c 28 29 [0-03] 6c 6f 6c 20 3d 20 [0-16] 2e [0-16] 2e 54 61 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}