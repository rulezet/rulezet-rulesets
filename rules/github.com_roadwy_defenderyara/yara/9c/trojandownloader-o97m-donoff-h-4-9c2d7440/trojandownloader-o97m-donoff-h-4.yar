rule TrojanDownloader_O97M_Donoff_H_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 20 28 32 20 5e 20 28 38 20 2a 20 28 33 20 2d } 		$a_00_1 = {3d 20 31 20 54 68 65 6e 20 44 65 62 75 67 2e 41 73 73 65 72 74 20 4e 6f 74 20 } 		$a_00_2 = {44 61 79 28 4e 6f 77 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a } 		$a_00_3 = {44 6f 45 76 65 6e 74 73 0d 0a 44 65 62 75 67 2e 50 72 69 6e 74 20 31 20 2f 20 30 0d 0a } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}