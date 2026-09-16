rule TrojanDownloader_O97M_Encdoc_PKE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 22 20 2b 20 22 6d 22 20 2b 20 22 64 } 		$a_01_1 = {3d 20 22 6d 73 67 62 6f 78 2f 72 6d 22 20 2b 20 22 73 68 22 20 2b 20 22 74 61 } 		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f } 		$a_01_3 = {3d 20 22 73 6e 69 70 70 65 74 73 2f 68 6f 67 79 61 2f } 		$a_01_4 = {3d 20 75 35 20 2b 20 75 36 20 2b 20 75 37 20 2b 20 75 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}