rule TrojanDownloader_O97M_Donoff_DRC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 77 72 69 74 65 20 78 48 74 74 70 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } 		$a_03_1 = {6d 61 69 6c 73 65 6e 64 69 6e 67 2e 73 69 74 65 2f 48 61 70 70 79 5f 43 53 2f 68 61 70 70 79 46 75 6e 2e 65 78 65 22 2c 20 46 61 6c 73 65 90 0a 44 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f } 		$a_03_2 = {57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f 4d 69 63 72 6f 73 6f 66 74 20 57 6f 72 6c 64 2e 65 78 65 22 90 0a 32 00 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 2f 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}