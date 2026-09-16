rule TrojanDownloader_O97M_Qakbot_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 70 73 3a 2f 2f 6d 69 2d 78 69 61 6f 6d 69 2e 6c 69 76 65 2f 79 54 69 4e 32 4a 4c 37 2f 4b 2e 70 6e 67 } 		$a_01_1 = {74 74 70 73 3a 2f 2f 64 65 76 2e 61 70 62 2e 63 6f 6d 2e 6c 61 2f 53 31 64 42 54 56 31 79 54 2f 4b 2e 70 6e 67 } 		$a_01_2 = {74 74 70 73 3a 2f 2f 61 73 73 61 6d 63 61 72 65 65 72 2e 6e 65 77 73 2f 50 43 59 78 5a 42 70 62 66 77 4e 2f 4b 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}