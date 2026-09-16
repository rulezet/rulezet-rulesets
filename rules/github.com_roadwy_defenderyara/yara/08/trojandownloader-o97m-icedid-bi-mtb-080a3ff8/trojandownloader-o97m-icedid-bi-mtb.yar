rule TrojanDownloader_O97M_IcedId_BI_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 2c 3a 2c 5c 2c 6a 2c 76 2c 61 2c 71 2c 62 2c 6a 2c 66 2c 5c 2c 66 2c 6c 2c 66 2c 67 2c 72 2c 7a 2c 33 2c 32 2c 5c 2c 7a 2c 66 2c 75 2c 67 2c 6e 2c 2e 2c 72 2c 6b 2c 72 2c 22 } 		$a_01_1 = {3d 20 61 5a 66 6c 32 57 28 52 65 70 6c 61 63 65 28 61 79 5a 49 6d 2c 20 61 4e 4a 32 52 6e 2c 20 22 22 29 29 } 		$a_01_2 = {61 74 62 75 52 63 2e 65 78 65 63 20 61 4f 6c 34 42 68 } 		$a_01_3 = {61 52 31 55 68 20 28 61 47 52 39 62 20 26 20 22 20 22 20 26 20 61 35 52 58 6a 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}