rule TrojanDownloader_O97M_Powdow_EM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 75 74 6f 2d 6d 65 6e 74 6f 2e 68 75 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 67 75 69 64 65 2f 39 } 		$a_01_1 = {65 6d 70 5c 6d 72 36 35 31 39 2e 65 78 65 } 		$a_01_2 = {54 66 61 38 73 37 31 4d 56 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}