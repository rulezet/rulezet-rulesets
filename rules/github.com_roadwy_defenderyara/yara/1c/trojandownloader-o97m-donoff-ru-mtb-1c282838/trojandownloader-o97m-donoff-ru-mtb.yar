rule TrojanDownloader_O97M_Donoff_RU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } 		$a_01_1 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d 20 } 		$a_01_2 = {45 36 73 69 7a 58 38 5a 2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}