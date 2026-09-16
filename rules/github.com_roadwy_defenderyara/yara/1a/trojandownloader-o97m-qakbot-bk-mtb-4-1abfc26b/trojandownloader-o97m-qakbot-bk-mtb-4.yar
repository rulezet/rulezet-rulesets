rule TrojanDownloader_O97M_Qakbot_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 61 4d 53 49 4f 20 26 20 22 5c 6d 31 2e 78 73 6c 22 } 		$a_01_1 = {3d 20 61 4d 53 49 4f 20 26 20 22 5c 6d 31 2e 63 6f 6d 22 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } 		$a_01_3 = {61 64 46 57 41 2e 72 75 6e 20 61 58 6f 34 76 70 20 26 20 61 52 6c 4d 79 78 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6d 45 32 61 6b 20 26 20 61 39 44 7a 35 74 20 26 20 61 6d 45 32 61 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}