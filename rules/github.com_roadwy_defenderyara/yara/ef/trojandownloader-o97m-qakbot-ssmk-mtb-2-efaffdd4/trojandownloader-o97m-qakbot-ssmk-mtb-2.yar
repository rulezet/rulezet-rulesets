rule TrojanDownloader_O97M_Qakbot_SSMK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 75 6e 69 72 6f 73 73 2e 73 69 74 65 2f 53 56 6d 47 74 46 57 55 4e 57 73 2f 49 2e 70 6e 67 } 		$a_01_1 = {74 74 70 73 3a 2f 2f 61 6c 65 78 61 64 72 69 76 69 6e 67 73 63 68 6f 6f 6c 2e 6f 6e 6c 69 6e 65 2f 56 69 61 61 77 4e 42 77 2f 49 2e 70 6e 67 } 		$a_01_2 = {74 74 70 73 3a 2f 2f 61 64 62 6f 61 74 2e 6c 69 76 65 2f 54 43 41 31 6f 69 71 6b 41 2f 49 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}