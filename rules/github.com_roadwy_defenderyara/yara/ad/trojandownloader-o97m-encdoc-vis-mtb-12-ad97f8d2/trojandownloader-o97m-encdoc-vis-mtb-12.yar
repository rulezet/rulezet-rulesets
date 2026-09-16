rule TrojanDownloader_O97M_EncDoc_VIS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 22 26 43 48 41 52 28 31 31 31 29 26 22 61 64 54 6f 46 69 6c 65 41 } 		$a_01_1 = {74 74 70 3a 2f 2f 31 38 38 2e 31 32 37 2e 32 35 34 2e 36 31 2f 38 39 37 38 36 34 35 34 36 35 37 36 34 35 2e 65 78 65 } 		$a_01_2 = {45 58 45 43 28 22 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}