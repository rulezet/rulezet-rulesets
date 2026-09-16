rule TrojanDownloader_O97M_Obfuse_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 65 6c 5f 68 48 } 		$a_01_1 = {2e 52 75 6e 28 49 42 53 59 5f 61 6c 34 6d 79 73 64 44 31 72 4d 4a 4a 4c 38 75 } 		$a_01_2 = {50 4d 61 44 39 62 74 7a 4d 45 5f 71 4e 48 73 6a 73 75 45 20 3d 20 5a 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}