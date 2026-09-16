rule TrojanDownloader_O97M_EncDoc_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 6f 75 72 73 74 61 72 73 2e 63 79 6f 75 2f 31 2e 70 68 70 } 		$a_01_1 = {5c 39 31 39 31 39 2e 64 6c 6c } 		$a_01_2 = {55 52 4c 4d 6f 6e } 		$a_01_3 = {6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}