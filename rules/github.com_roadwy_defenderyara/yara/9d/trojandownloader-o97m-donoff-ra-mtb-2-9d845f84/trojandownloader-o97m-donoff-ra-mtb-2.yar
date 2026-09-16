rule TrojanDownloader_O97M_Donoff_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 72 72 61 79 6d 61 69 6e 28 69 29 2e 64 61 74 65 5f 62 6f 72 72 6f 77 65 64 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e } 		$a_01_1 = {61 72 72 61 79 6d 61 69 6e 28 69 29 2e 64 61 74 65 5f 64 75 65 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 68 61 73 64 6f 6f 6b 64 6b 77 64 69 61 68 73 69 64 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}