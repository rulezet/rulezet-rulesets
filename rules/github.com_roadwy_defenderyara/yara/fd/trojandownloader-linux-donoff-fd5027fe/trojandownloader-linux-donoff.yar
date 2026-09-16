rule TrojanDownloader_Linux_Donoff{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,2b 00 2b 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 5f 4f 70 65 6e } 		$a_01_1 = {43 68 72 28 31 } 		$a_01_2 = {43 68 72 28 34 } 		$a_01_3 = {53 67 6e 28 } 		$a_01_4 = {22 20 2b 20 22 22 20 2b 20 22 } 		$a_01_5 = {22 20 26 20 22 } 		$a_01_6 = {2e 4f 70 65 6e 20 22 47 45 54 22 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=43
 
}