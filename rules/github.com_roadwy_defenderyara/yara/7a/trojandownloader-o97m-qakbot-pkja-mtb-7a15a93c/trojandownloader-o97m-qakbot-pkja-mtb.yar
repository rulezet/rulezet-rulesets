rule TrojanDownloader_O97M_Qakbot_PKJA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 63 6f 6d 6d 65 72 63 65 73 68 6f 70 2e 63 6f 6d 2f [0-14] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 } 		$a_03_1 = {64 63 72 69 61 63 6f 65 73 2e 63 6f 6d 2e 62 72 2f [0-14] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 } 		$a_03_2 = {63 6f 62 72 61 6d 6f 74 6f 73 2e 63 6f 6d 2e 62 72 2f [0-14] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}