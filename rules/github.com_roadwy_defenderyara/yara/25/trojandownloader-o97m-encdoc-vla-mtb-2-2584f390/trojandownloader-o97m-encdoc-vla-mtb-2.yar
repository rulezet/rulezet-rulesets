rule TrojanDownloader_O97M_EncDoc_VLA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 6a 2e 6d 70 2f } 		$a_01_1 = {61 73 6b 73 64 64 61 70 6f 6f 70 62 6e 6e 62 6e 62 74 79 71 77 6b 64 } 		$a_01_2 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 29 2e 53 68 65 6c 6c 65 78 65 63 75 74 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}