rule TrojanDownloader_O97M_Obfuse_RU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 } 		$a_03_1 = {70 61 73 74 65 2e 65 65 2f 72 2f 76 35 65 38 45 90 0a 1b 00 68 74 27 2b 27 74 70 3a 2f 2f } 		$a_00_2 = {4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 } 		$a_00_3 = {77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}