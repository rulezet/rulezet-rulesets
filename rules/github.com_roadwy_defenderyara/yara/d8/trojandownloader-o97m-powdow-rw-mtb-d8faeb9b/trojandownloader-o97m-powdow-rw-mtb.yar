rule TrojanDownloader_O97M_Powdow_RW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } 		$a_03_1 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 78 73 7a 62 32 6a 90 0a 1f 00 68 74 27 2b 27 74 70 73 3a 2f 2f } 		$a_00_2 = {4f 75 74 46 69 6c 65 } 		$a_00_3 = {74 65 73 74 35 27 2b 27 2e 65 78 65 27 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}