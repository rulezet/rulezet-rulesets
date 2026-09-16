rule TrojanDownloader_O97M_Powdow_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 70 6f 5e 77 65 72 73 68 } 		$a_01_1 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 } 		$a_01_2 = {74 74 70 3a 2f 2f 68 6f 74 65 6c 63 6f 6e 74 69 6e 65 6e 74 61 6c 2d 6b 68 65 6e 69 66 72 61 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 67 79 74 30 39 31 32 33 36 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}