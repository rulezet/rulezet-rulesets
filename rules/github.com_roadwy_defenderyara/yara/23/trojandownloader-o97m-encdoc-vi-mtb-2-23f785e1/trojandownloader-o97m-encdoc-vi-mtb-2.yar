rule TrojanDownloader_O97M_EncDoc_VI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 20 22 22 2c 20 22 63 6d 64 2e 65 78 65 20 2f 73 20 2f 63 20 } 		$a_01_1 = {56 42 41 2e 53 68 65 6c 6c } 		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 } 		$a_01_3 = {63 3a 5c 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 5c 69 6e 64 65 78 2e 68 } 		$a_01_4 = {50 75 62 6c 69 63 20 53 75 62 20 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}