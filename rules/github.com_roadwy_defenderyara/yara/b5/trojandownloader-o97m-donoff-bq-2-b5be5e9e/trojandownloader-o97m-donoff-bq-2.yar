rule TrojanDownloader_O97M_Donoff_BQ_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {22 5c 73 63 61 6c 65 64 2e 65 78 65 22 } 		$a_00_1 = {22 71 75 61 64 72 69 66 6f 6c 69 6f 6c 61 74 65 } 		$a_00_2 = {45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 49 4e 33 32 5f 50 72 6f 64 75 63 74 20 57 48 45 52 45 20 4e 61 6d 65 20 4c 49 4b 45 20 27 50 79 74 68 6f 6e 20 25 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}