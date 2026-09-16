rule TrojanDownloader_O97M_Obfuse_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 36 37 2e 39 39 2e 35 30 2e 31 32 39 2f 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 22 2c 20 46 61 6c 73 65 } 		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 5c 54 65 6d 70 5c 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 22 2c } 		$a_01_2 = {53 68 65 6c 6c 20 28 22 72 75 6e 64 6c 6c 33 32 20 43 3a 5c 54 65 6d 70 5c 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 2c 20 76 4f 75 6f 76 4b 4d 6a 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}