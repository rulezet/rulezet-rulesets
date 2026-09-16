rule TrojanDownloader_O97M_Bartallex_5{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 69 20 3d 20 4c 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 20 54 6f 20 55 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 } 		$a_01_1 = {4f 62 6a 49 6e 64 65 78 20 3d 20 4f 62 6a 49 6e 64 65 78 20 26 20 43 68 72 28 } 		$a_01_2 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}