rule TrojanDownloader_O97M_Bartallex_C_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 4d 59 5f 46 49 4c 44 49 52 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 } 		$a_01_1 = {4d 6f 64 75 6c 65 31 2e } 		$a_01_2 = {63 69 6e 74 6f 73 68 3b 20 49 6e 74 65 6c 20 4d 61 63 20 4f 53 20 58 } 		$a_01_3 = {43 68 72 28 33 34 } 		$a_01_4 = {43 68 72 28 31 31 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}