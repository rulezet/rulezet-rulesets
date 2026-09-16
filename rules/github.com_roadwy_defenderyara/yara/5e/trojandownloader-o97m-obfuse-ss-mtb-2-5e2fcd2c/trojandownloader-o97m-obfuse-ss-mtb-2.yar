rule TrojanDownloader_O97M_Obfuse_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 61 6f 6b 73 64 6f 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 7a 61 69 6d 2e 6a 73 22 } 		$a_01_1 = {53 68 65 65 74 31 2e 52 61 6e 67 65 20 28 22 4f 32 32 39 22 29 } 		$a_01_2 = {43 61 6c 6c 20 53 68 65 6c 6c 25 28 77 67 70 72 43 34 59 78 7a 63 6b 48 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}