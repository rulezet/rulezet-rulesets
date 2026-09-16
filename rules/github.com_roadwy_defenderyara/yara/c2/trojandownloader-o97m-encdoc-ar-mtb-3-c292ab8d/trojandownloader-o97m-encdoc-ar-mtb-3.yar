rule TrojanDownloader_O97M_EncDoc_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6a 6d 64 6d 65 6e 73 77 65 61 72 2e 63 6f 6d 2f 64 76 78 71 69 2f 44 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 6a 6d 64 6d 65 6e 73 77 65 61 72 2e 63 6f 6d 2f 64 76 78 71 69 2f 35 33 30 33 34 30 2e 70 6e 67 } 		$a_01_2 = {43 3a 5c 44 61 74 6f 70 5c } 		$a_01_3 = {7a 69 70 66 6c 64 72 } 		$a_01_4 = {4a 4a 43 43 43 4a } 		$a_01_5 = {64 54 6f 46 69 6c 65 41 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}