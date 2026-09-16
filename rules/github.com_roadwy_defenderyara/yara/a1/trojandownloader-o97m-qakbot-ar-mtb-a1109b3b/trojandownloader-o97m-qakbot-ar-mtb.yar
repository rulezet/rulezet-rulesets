rule TrojanDownloader_O97M_Qakbot_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 32 35 34 37 35 30 2e 70 6e 67 } 		$a_01_1 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } 		$a_01_2 = {4f 70 65 6e 55 52 4c } 		$a_01_3 = {68 74 74 70 3a 2f 2f 64 69 6d 61 73 2e 73 74 69 66 61 72 2e 61 63 2e 69 64 2f 76 6a 72 7a 7a 75 66 73 75 2f } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=30
 
}