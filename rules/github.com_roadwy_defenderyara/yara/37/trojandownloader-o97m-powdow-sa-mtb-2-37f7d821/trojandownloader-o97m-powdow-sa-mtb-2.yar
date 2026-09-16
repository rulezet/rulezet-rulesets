rule TrojanDownloader_O97M_Powdow_SA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 73 64 6d 61 73 69 64 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 70 2f 2e 6d 40 6a 34 38 30 39 32 33 25 31 34 38 30 39 32 33 2f 31 3a 2f 74 70 68 74 20 22 29 29 } 		$a_01_1 = {6b 61 6b 73 6d 64 39 61 73 64 6d 20 3d 20 } 		$a_01_2 = {78 6d 6f 72 67 61 6e 64 64 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 6e 67 70 69 22 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}