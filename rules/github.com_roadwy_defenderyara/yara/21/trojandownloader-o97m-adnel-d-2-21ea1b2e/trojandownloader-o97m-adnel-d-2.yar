rule TrojanDownloader_O97M_Adnel_D_2{
	meta:
		description = "TrojanDownloader:O97M/Adnel.D,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 75 72 79 79 2e 4e 63 63 79 76 70 6e 67 76 62 61 } 		$a_01_1 = {4e 51 42 51 4f 2e 46 67 65 72 6e 7a } 		$a_01_2 = {46 70 65 76 63 67 76 61 74 2e 53 76 79 72 46 6c 66 67 72 7a 42 6f 77 72 70 67 } 		$a_01_3 = {5a 46 4b 5a 59 32 2e 4b 5a 59 55 47 47 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}