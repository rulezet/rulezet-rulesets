rule TrojanDownloader_O97M_Donoff_188{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 46 4e 42 50 4c 46 43 20 3d 20 4b 6f 6d 62 61 69 6e 65 72 28 22 54 4f 4f 43 69 63 72 6f 54 4f 4f 4f 43 6f 66 74 2e 58 54 4f 4f 43 4c 48 54 54 50 54 4f 4f 4f 4f 43 41 64 6f 64 62 2e 54 4f 4f 4f 43 74 72 54 4f 43 61 54 4f 4f 43 54 4f 4f 4f 4f 43 54 4f 4f 4f 43 68 54 4f 43 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 54 4f 4f 4f 4f 43 57 54 4f 4f 4f 43 63 72 69 70 74 2e 54 4f 4f 4f 43 68 54 4f 43 6c 6c 54 4f 4f 4f 4f 43 50 72 6f 63 54 4f 43 54 4f 4f 4f 43 54 4f 4f 4f 43 54 4f 4f 4f 4f 43 47 54 4f 43 54 54 4f 4f 4f 4f 43 54 54 4f 43 54 4f 4f 43 50 54 4f 4f 4f 4f 43 54 79 70 54 4f 43 54 4f 4f 4f 4f 43 6f 70 54 4f 43 6e 54 4f 4f 4f 4f 43 77 72 69 74 54 4f 43 54 4f 4f 4f 4f 43 72 54 4f 43 54 4f 4f 4f 43 70 6f 6e 54 4f 4f 4f 43 54 4f 43 42 6f 64 79 } 		$a_01_1 = {6d 41 73 68 69 6e 6b 61 7a 69 6e 67 65 72 61 49 67 6f 6c 6f 63 68 6b 75 53 6c 6f 6d 61 6c 61 5f 74 6f 5f 5f 31 2e 53 65 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}