rule TrojanDownloader_O97M_EncDoc_ALA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 73 75 72 76 65 69 6c 6c 61 6e 74 66 69 72 65 2e 63 22 26 22 6f 22 26 22 6d 2f 73 46 75 6a 4f 65 69 4d 30 56 42 2f 61 6c 70 2e 68 74 6d 6c } 		$a_01_1 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 61 72 74 61 64 69 64 61 63 74 69 63 61 2e 72 6f 2f 38 64 73 6a 41 62 42 6d 49 4a 55 75 2f 61 6c 70 2e 68 74 6d 6c } 		$a_01_2 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 73 61 6e 62 61 72 69 2e 6d 78 2f 4d 73 50 38 65 35 59 78 70 2f 61 6c 70 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}