rule TrojanDownloader_O97M_EncDoc_YAJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 61 6e 6f 6e 6c 69 6e 65 2e 69 6e 2f 73 61 68 78 69 66 77 6f 6d 63 7a 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } 		$a_00_1 = {43 3a 5c 46 65 74 69 6c 5c 47 69 6f 6c 61 5c 6f 63 65 61 6e 44 68 } 		$a_01_2 = {6c 65 79 64 65 72 6f 6d 70 69 65 6e 74 65 73 2e 63 6c 2f 79 77 68 62 6e 69 7a 79 6c 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}