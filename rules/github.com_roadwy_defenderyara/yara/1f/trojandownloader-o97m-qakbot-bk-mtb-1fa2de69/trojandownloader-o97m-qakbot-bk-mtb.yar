rule TrojanDownloader_O97M_Qakbot_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 61 35 44 39 33 79 20 26 20 22 20 22 20 26 20 61 5a 4f 65 38 61 } 		$a_01_1 = {3d 20 22 31 30 2e 32 33 2e 33 31 2e 33 2e 30 2e 32 39 2e 31 30 2e 32 39 22 } 		$a_01_2 = {3d 20 53 70 6c 69 74 28 61 77 6f 51 6e 32 2c 20 22 2e 22 29 } 		$a_01_3 = {3d 20 61 6d 47 70 69 28 61 33 5a 6c 57 47 28 61 63 58 54 44 30 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}