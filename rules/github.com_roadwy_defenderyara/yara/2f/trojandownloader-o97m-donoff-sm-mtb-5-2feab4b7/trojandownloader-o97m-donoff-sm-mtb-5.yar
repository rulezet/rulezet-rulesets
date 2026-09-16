rule TrojanDownloader_O97M_Donoff_SM_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 20 3d 20 22 6d 73 68 74 61 2e 65 78 65 20 22 } 		$a_01_1 = {59 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } 		$a_01_2 = {5a 20 3d 20 22 6b 64 64 6a 6b 64 77 6f 6b 64 64 77 6f 64 6b 77 6f 64 6b 69 22 } 		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 58 20 2b 20 59 20 2b 20 5a 29 29 } 		$a_01_4 = {41 75 74 6f 5f 4f 70 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}