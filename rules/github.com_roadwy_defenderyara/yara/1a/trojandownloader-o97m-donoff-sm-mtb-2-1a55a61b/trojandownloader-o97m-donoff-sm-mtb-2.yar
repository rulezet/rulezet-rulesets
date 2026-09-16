rule TrojanDownloader_O97M_Donoff_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 41 64 64 20 22 4d 73 48 74 22 } 		$a_01_1 = {2e 41 64 64 20 22 61 20 68 74 74 70 3a 2f 2f 22 } 		$a_01_2 = {2e 41 64 64 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 6b 6a 61 73 64 68 73 75 64 69 71 6f 77 69 75 64 71 77 22 } 		$a_01_3 = {6f 62 6a 2e 4d 61 69 6e 43 61 6c 6c 65 78 20 28 64 64 31 20 2b 20 64 64 32 20 2b 20 64 64 33 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}