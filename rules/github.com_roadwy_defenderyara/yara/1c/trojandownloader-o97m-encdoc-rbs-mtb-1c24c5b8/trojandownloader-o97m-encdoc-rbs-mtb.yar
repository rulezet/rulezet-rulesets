rule TrojanDownloader_O97M_EncDoc_RBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 6d 70 5c 4c 75 75 4e 67 61 79 41 } 		$a_01_1 = {43 3a 5c 63 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 3d 6d 64 20 63 3a 5c 74 6d 70 } 		$a_01_2 = {63 3a 5c 74 6d 70 5c 2a 2e 2a } 		$a_01_3 = {41 75 74 6f 5f 4f 70 65 6e 3a 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}