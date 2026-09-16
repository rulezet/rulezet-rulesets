rule TrojanDownloader_O97M_EncDoc_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 72 6d 62 76 6d 64 71 2e 65 78 65 } 		$a_01_1 = {55 52 4c 4d 4f 4e } 		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}