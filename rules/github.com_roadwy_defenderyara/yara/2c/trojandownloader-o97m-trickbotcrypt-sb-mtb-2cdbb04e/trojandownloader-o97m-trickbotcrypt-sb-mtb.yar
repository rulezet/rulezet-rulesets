rule TrojanDownloader_O97M_TrickbotCrypt_SB_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 70 65 6e 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 64 6f 74 2e 6a 70 65 67 } 		$a_00_1 = {73 75 62 6d 6f 6f 6e 6c 69 67 68 74 28 29 } 		$a_00_2 = {77 6f 72 6b 73 68 65 65 74 73 28 22 74 61 62 6c 65 6f 66 63 6f 6e 74 65 6e 74 22 29 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}