rule TrojanDownloader_O97M_Obfuse_FRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6b 2e 63 6c 6f 6e 65 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } 		$a_01_1 = {6b 2e 6f 70 65 6e 65 72 2e 47 72 6f 75 70 4e 61 6d 65 } 		$a_03_2 = {53 75 62 20 5f 90 0c 02 00 41 75 74 6f 5f 63 6c 6f 73 65 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}