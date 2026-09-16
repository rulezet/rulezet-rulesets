rule TrojanDownloader_O97M_EncDoc_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 6f 72 74 69 6e 61 73 74 65 6c 61 73 79 74 72 61 7a 6f 73 2e 63 6f 6d 2f 59 72 6f 36 41 74 76 6a 2f 73 65 63 2e 68 74 6d 6c } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 6f 72 71 75 69 64 65 61 76 61 6c 6c 65 6e 61 74 61 2e 63 6f 6d 2f 34 6a 6d 44 62 30 73 39 73 67 2f 73 65 63 2e 68 74 6d 6c } 		$a_01_2 = {68 74 74 70 73 3a 2f 2f 66 75 6e 64 61 63 69 6f 6e 76 65 72 64 61 64 65 72 6f 73 68 65 72 6f 65 73 2e 63 6f 6d 2f 67 59 30 4f 70 35 4a 6b 68 74 2f 73 65 63 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}