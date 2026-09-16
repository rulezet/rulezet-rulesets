rule TrojanDownloader_Linux_Donoff_8{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-40] 3a [0-05] 2f [0-10] 2e 65 78 65 } 		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } 		$a_01_2 = {41 75 74 6f 5f 4f 70 65 6e } 		$a_01_3 = {45 6e 76 69 72 6f 6e } 		$a_01_4 = {53 68 65 6c 6c } 		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 69 73 73 61 79 2e 63 6f 2e 6a 70 2f 6b 6f 6a 69 6e 2f 73 68 6f 68 69 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*-100) >=5
 
}