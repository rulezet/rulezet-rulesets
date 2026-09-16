rule TrojanDownloader_O97M_Obfuse_PAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 42 5f 4e 61 6d 65 20 3d 20 22 76 61 72 46 75 6e 63 50 74 72 22 } 		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 74 6f 72 61 67 65 41 72 67 4c 69 62 28 22 6c 6c 65 68 73 2e 74 70 69 72 63 73 77 22 29 29 2e } 		$a_01_2 = {3d 20 4d 69 64 28 6c 6f 61 64 4c 69 73 74 62 6f 78 2c 20 6d 65 6d 54 65 78 74 62 6f 78 2c 20 31 30 30 30 30 30 30 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}