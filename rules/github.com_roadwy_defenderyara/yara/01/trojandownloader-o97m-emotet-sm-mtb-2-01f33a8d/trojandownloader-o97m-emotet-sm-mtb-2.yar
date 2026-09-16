rule TrojanDownloader_O97M_Emotet_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } 		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } 		$a_01_2 = {3d 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 } 		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}