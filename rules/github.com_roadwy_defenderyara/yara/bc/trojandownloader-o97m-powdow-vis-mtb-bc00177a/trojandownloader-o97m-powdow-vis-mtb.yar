rule TrojanDownloader_O97M_Powdow_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_1 = {62 79 70 61 73 73 20 73 74 41 52 74 } 		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 38 70 62 6f 77 6e 74 } 		$a_01_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}