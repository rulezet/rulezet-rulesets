rule TrojanDownloader_O97M_Donoff_RA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 31 20 3d 20 22 65 63 68 22 20 2b 20 22 6f 20 73 74 61 72 74 22 20 26 20 22 20 63 61 22 0d 0a 63 6f 6d 32 20 3d 20 22 6c 63 20 3e 3e 20 25 74 65 6d 70 25 5c 32 2e 74 78 74 22 0d 0a 63 6f 6d 33 20 3d 20 63 6f 6d 31 20 2b 20 63 6f 6d 32 } 		$a_01_1 = {53 65 74 20 6f 62 6a 73 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}