rule TrojanDownloader_O97M_TrickbotCrypt_SB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2e 63 72 65 61 74 65 74 65 78 74 66 69 6c 65 28 22 63 3a 5c [0-20] 5c [0-20] 2e 76 62 22 2b 22 73 22 29 } 		$a_02_1 = {2e 63 72 65 61 74 65 66 6f 6c 64 65 72 28 22 63 3a 5c [0-20] 5c [0-20] 22 29 } 		$a_02_2 = {2e 65 78 65 63 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 63 3a 5c [0-20] 5c [0-20] 2e 76 62 22 2b 22 73 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}