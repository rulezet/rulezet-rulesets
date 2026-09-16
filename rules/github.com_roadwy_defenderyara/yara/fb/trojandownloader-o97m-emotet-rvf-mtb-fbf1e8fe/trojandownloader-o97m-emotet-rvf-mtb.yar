rule TrojanDownloader_O97M_Emotet_RVF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 61 72 64 61 72 63 79 2e 63 6f 6d 2f 63 73 73 2f 4e 48 47 79 54 54 43 4b 2f 22 2c 22 } 		$a_01_1 = {64 69 6a 69 63 6f 6d 2e 6e 65 74 2f 65 72 72 6f 72 2f 35 78 7a 58 64 44 2f 22 2c 22 } 		$a_01_2 = {74 70 2e 63 6f 6d 70 72 69 62 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 50 7a 67 72 38 71 65 78 6e 2f 22 2c 22 } 		$a_01_3 = {68 72 61 6e 65 6e 69 65 2e 70 65 72 65 65 7a 64 2d 32 34 2e 63 6f 6d 2f 31 2f 75 45 69 62 75 49 71 68 5a 69 34 6f 75 61 2f 22 2c 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}