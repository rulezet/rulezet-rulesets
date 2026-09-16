rule TrojanDownloader_O97M_Emotet_SSMK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 79 6d 69 63 72 6f 67 72 65 65 6e 2e 6d 69 67 68 74 63 6f 64 65 2e 63 6f 6d 2f 46 6f 78 2d 43 2f 68 6c 48 56 2f } 		$a_01_1 = {3a 2f 2f 31 38 38 2e 31 36 36 2e 5d 32 34 35 2e 31 31 32 2f 74 65 6d 70 6c 61 74 65 2f 52 79 6b 2f } 		$a_01_2 = {3a 2f 2f 34 37 2e 5d 32 34 34 2e 31 38 39 2e 5d 37 33 2f 2d 2d 2f 65 72 32 79 41 35 4c 6b 52 63 58 72 54 30 51 2f } 		$a_01_3 = {3a 2f 2f 77 77 77 2e 64 6e 61 75 74 69 6b 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 76 54 41 52 48 52 4b 48 6a 52 71 6b 47 4b 55 2f } 		$a_01_4 = {3a 2f 2f 61 6c 2d 62 72 69 6b 2e 63 6f 6d 2f 76 62 2f 45 42 42 37 46 75 61 57 6e 4a 6d 2f } 		$a_01_5 = {3a 2f 2f 62 75 6c 6c 64 6f 67 69 72 6f 6e 77 6f 72 6b 73 6c 6c 63 2e 63 6f 6d 2f 74 65 6d 70 2f 36 55 79 4e 75 38 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}