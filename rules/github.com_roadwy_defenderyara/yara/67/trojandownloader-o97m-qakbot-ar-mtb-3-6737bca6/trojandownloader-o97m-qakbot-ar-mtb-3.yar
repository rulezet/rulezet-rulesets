rule TrojanDownloader_O97M_Qakbot_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 49 6f 70 73 64 5c } 		$a_00_1 = {68 74 74 70 3a 2f 2f 74 72 61 64 75 63 65 72 65 6a 75 72 69 64 69 63 61 2e 72 6f 2f 74 65 6e 6c 78 68 6c 7a 70 61 67 63 2f 44 } 		$a_00_2 = {68 74 74 70 3a 2f 2f 74 72 61 64 75 63 65 72 65 6a 75 72 69 64 69 63 61 2e 72 6f 2f 74 65 6e 6c 78 68 6c 7a 70 61 67 63 2f 36 32 35 39 38 36 2e 70 6e 67 } 		$a_00_3 = {65 78 65 07 00 00 7a 69 70 66 6c 64 72 03 00 00 4d 6f 6e 06 00 00 4a 4a 43 43 43 4a } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*20+(#a_00_2  & 1)*20+(#a_00_3  & 1)*10) >=20
 
}