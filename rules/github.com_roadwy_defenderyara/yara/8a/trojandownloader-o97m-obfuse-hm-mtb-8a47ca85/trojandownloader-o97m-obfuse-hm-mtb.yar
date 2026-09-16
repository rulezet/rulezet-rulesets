rule TrojanDownloader_O97M_Obfuse_HM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 6d 69 6e 70 69 63 2e 64 65 2f 6b 2f 62 63 31 6c 2f 31 36 70 74 75 73 2f 90 0a 24 00 68 74 74 70 73 3a 2f 2f } 		$a_01_1 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } 		$a_03_2 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 90 0a 24 00 53 68 65 6c 6c 20 22 43 3a 5c } 		$a_01_3 = {45 6e 64 20 53 75 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}