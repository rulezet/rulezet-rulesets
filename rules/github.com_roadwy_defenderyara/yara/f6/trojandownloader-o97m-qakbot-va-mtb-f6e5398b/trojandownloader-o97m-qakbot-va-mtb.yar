rule TrojanDownloader_O97M_Qakbot_VA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 67 76 6e 70 73 64 } 		$a_01_1 = {5c 62 72 61 76 61 67 2e 65 78 65 } 		$a_01_2 = {4a 4a 43 43 43 4a 4a } 		$a_01_3 = {52 6f 75 74 } 		$a_01_4 = {65 78 70 6c } 		$a_01_5 = {55 52 4c 44 6f 77 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}