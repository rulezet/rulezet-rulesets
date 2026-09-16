rule TrojanDownloader_O97M_EncDoc_R_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b } 		$a_01_1 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 } 		$a_01_2 = {3d 20 22 2e 6a 2e 6d 70 2f } 		$a_03_3 = {6a 2e 6d 70 2f 61 6a 64 64 64 73 64 73 64 6a 73 6a 63 6a 6f 73 64 6a 90 0a 3f 00 68 74 74 70 3a 2f 2f 77 77 77 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3) >=3
 
}