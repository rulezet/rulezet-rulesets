rule TrojanDownloader_O97M_Powdow_PDG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 64 6f 78 69 74 69 6e 67 2e 63 6f 2e 7a 61 2f 77 70 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 46 55 4c 4c 46 4f 52 43 45 2e 65 78 65 22 22 20 } 		$a_01_1 = {26 26 20 50 71 64 61 68 69 73 6b 6f 74 68 6c 76 70 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}