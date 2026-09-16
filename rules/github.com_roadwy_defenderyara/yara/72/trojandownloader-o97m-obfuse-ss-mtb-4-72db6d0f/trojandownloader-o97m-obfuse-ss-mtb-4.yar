rule TrojanDownloader_O97M_Obfuse_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 49 69 62 59 43 6d 6d 58 55 28 66 6a 6b 65 72 6f 6f 6f 73 29 2c 20 49 69 62 59 43 6d 6d 58 55 28 66 67 66 6a 68 66 67 66 67 29 2c 20 22 22 2c 20 22 22 2c 20 30 } 		$a_01_1 = {49 69 62 59 43 6d 6d 58 55 20 3d 20 49 69 62 59 43 6d 6d 58 55 20 26 20 4d 69 64 28 73 2c 20 70 2c 20 31 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}