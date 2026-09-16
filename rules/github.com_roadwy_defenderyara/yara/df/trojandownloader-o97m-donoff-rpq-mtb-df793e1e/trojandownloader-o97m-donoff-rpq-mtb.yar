rule TrojanDownloader_O97M_Donoff_RPQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RPQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 32 30 2e 31 39 36 2e 32 31 33 2e 31 39 2f 66 69 72 65 77 61 6c 6c 2e 65 78 65 22 } 		$a_01_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 54 72 6f 75 62 6c 65 73 68 6f 6f 74 65 72 2e 7a 69 70 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}