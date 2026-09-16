rule TrojanDownloader_O97M_Donoff_RA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 61 76 31 2e 72 75 2f 66 61 72 2e 6d 73 69 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 66 65 72 31 2e 72 75 2f 66 66 2e 6d 73 69 } 		$a_01_2 = {68 74 74 70 3a 2f 2f 74 6f 76 31 2e 72 75 2f 74 6f 79 2e 6d 73 69 } 		$a_01_3 = {68 74 74 70 3a 2f 2f 65 6a 76 31 2e 72 75 2f 31 32 33 2e 6d 73 69 } 		$a_01_4 = {68 74 74 70 3a 2f 2f 66 66 67 68 2e 72 75 2f 6a 6a 2e 6d 73 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}