rule TrojanDownloader_O97M_Emotet_SSMK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 61 6e 64 68 69 74 6f 64 61 79 2e 6f 72 67 2f 76 69 64 65 6f 2f 36 4a 76 41 38 2f } 		$a_01_1 = {64 6a 75 6e 72 65 61 6c 2e 63 6f 2e 75 6b 2f 73 69 74 65 2f 41 70 4f 4b 70 46 61 64 2f } 		$a_01_2 = {6a 6f 68 6e 73 6f 6e 73 6d 65 64 69 61 2e 69 74 2f 69 6d 67 2f 5a 42 4e 6b 30 78 70 52 4c 38 59 45 56 6c } 		$a_01_3 = {67 65 6e 63 63 61 67 64 61 73 2e 63 6f 6d 2e 74 72 2f 61 73 73 65 74 73 2f 64 6f 57 48 49 78 4c 65 37 65 } 		$a_01_4 = {67 72 61 66 69 73 63 68 65 72 2e 63 68 2f 66 69 74 2d 77 65 6c 6c 2f 77 44 50 54 77 4b 74 5a 50 6f 57 4c 31 32 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}