rule TrojanDownloader_O97M_Donoff_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 72 65 69 32 2e } 		$a_01_1 = {3d 20 22 68 74 61 22 22 20 68 74 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}