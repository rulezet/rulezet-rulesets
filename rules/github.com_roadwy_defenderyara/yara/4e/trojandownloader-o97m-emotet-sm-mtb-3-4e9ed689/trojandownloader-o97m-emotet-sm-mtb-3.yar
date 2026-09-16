rule TrojanDownloader_O97M_Emotet_SM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 7a 68 64 6b 6a 65 77 } 		$a_01_1 = {26 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 76 6b 77 65 72 2e 62 61 74 } 		$a_01_2 = {56 42 5f 4e 61 6d 65 20 3d 20 22 48 44 73 66 67 52 64 73 34 68 74 6b 64 65 } 		$a_01_3 = {48 64 65 22 2c 20 22 22 } 		$a_01_4 = {61 56 53 45 22 2c 20 22 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}