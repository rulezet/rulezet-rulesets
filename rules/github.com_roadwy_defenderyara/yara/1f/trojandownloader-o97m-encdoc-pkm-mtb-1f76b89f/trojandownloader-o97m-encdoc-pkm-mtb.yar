rule TrojanDownloader_O97M_EncDoc_PKM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 61 79 2d 62 6e 6b 32 75 2e 63 6f 6d 2f 66 69 6c 65 73 2f 65 6e 71 75 69 72 79 2e 7a 69 70 } 		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 22 26 65 6e 76 69 72 6f 6e 28 22 75 73 65 72 6e 61 6d 65 22 29 26 22 5c 64 6f 63 75 6d 65 6e 74 73 5c 22 26 22 65 6e 71 75 69 72 79 2e 65 78 65 } 		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 6c 69 62 22 75 72 6c 6d 6f 6e 22 61 6c 69 61 73 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}