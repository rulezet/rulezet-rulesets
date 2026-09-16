rule TrojanDownloader_O97M_obfuse_DR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/obfuse.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 6c 62 39 6c 6d 74 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 36 2e 63 61 62 22 90 0a 2c 00 22 68 74 74 70 3a 2f 2f } 		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 } 		$a_00_2 = {2e 72 75 6e 20 22 72 65 67 73 76 72 33 32 20 31 2e 65 78 70 22 } 		$a_00_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } 		$a_00_4 = {4e 65 77 20 57 73 68 53 68 65 6c 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}