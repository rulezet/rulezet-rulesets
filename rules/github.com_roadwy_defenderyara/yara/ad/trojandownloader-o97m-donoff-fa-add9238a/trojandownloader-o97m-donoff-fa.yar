rule TrojanDownloader_O97M_Donoff_FA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 5e 69 5e 74 5e 73 5e 61 5e 64 5e 6d 69 6e 5e 20 2f 74 5e 72 61 5e 6e 5e 73 5e 66 5e 65 5e 72 5e 20 5e 2f 5e 64 5e 6f 5e 77 5e 6e 5e 6c 5e 6f 5e 61 5e 64 } 		$a_00_1 = {25 74 6d 70 25 2f 44 53 61 6a 49 4f 44 41 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}