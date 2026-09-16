rule TrojanDownloader_O97M_Qakbot_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 31 30 2e 32 33 2e 33 31 2e 33 2e 30 2e 32 39 2e 31 30 2e 32 39 22 } 		$a_01_1 = {53 68 65 6c 6c 20 61 64 4e 41 6a 20 26 20 22 20 22 20 26 20 61 32 55 71 69 6b } 		$a_01_2 = {3d 20 53 70 6c 69 74 28 61 33 64 6d 69 2c 20 22 2e 22 29 } 		$a_01_3 = {43 61 6c 6c 20 61 42 30 6e 76 64 28 61 32 55 71 69 6b 2c 20 61 68 72 55 38 56 28 61 57 66 6a 48 67 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}