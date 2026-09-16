rule TrojanDownloader_O97M_Qakbot_SSMK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 6d 79 70 68 61 6d 63 75 61 74 75 69 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 7a 31 62 39 59 66 48 6f 58 37 46 70 2f } 		$a_01_1 = {74 74 70 3a 2f 2f 6d 79 72 61 6d 61 72 6b 2e 63 6f 6d 2f 6d 61 69 6c 2f 72 68 45 50 79 6c 58 44 38 42 75 54 41 2f } 		$a_01_2 = {74 74 70 73 3a 2f 2f 6d 79 65 63 68 6f 70 72 6f 6a 65 63 74 2e 63 6f 6d 2f 70 69 74 74 65 72 70 61 74 74 65 72 2f 62 4e 78 2f } 		$a_01_3 = {74 74 70 3a 2f 2f 6d 79 62 69 73 63 6f 74 74 6f 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 42 44 63 6a 51 54 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}