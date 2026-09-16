rule TrojanDownloader_O97M_Donoff_RP_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 78 6f 6f 6d 65 72 2e 76 69 72 67 69 6c 69 6f 2e 69 74 2f 6c 75 64 6f 72 6d 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2e 68 74 6d } 		$a_01_1 = {45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 22 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 65 72 72 6f 72 66 69 78 2e 62 61 74 } 		$a_01_2 = {66 72 6d 43 68 65 73 73 58 2e 52 6f 6f 74 4f 4c 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}