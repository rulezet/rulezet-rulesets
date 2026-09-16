rule TrojanDownloader_O97M_EncDoc_VLA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 70 73 3a 2f 2f 72 22 26 22 65 63 61 70 69 74 6f 6c 2e 63 6f 6d 2f 74 6c 36 69 6c 4b 59 31 74 38 72 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } 		$a_01_1 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 73 22 26 22 77 65 65 62 65 7a 2e 63 6f 6d 2f 51 48 61 48 65 43 6e 52 72 56 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } 		$a_01_2 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 6d 22 26 22 68 6a 6c 61 62 2e 6d 6c 2f 32 65 69 65 31 4a 4e 73 51 42 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}