rule TrojanDownloader_O97M_Obfuse_JM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 22 22 22 20 2b 20 22 22 20 2b 20 22 6d 73 22 20 2b 20 22 68 74 61 22 22 22 22 22 20 2b 20 22 68 74 74 70 73 22 20 2b 20 22 3a 5c 5c [0-14] 40 6a 2e 6d 70 5c [0-18] 22 22 22 } 		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 		$a_01_2 = {53 75 62 20 63 61 6c 63 75 6c 61 74 6f 72 28 29 } 		$a_01_3 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}