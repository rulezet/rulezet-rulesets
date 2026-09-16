rule TrojanDownloader_O97M_Donoff_CG{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CG,SIGNATURE_TYPE_MACROHSTR_EXT,ffffff90 01 ffffff90 01 05 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 43 6c 6f 73 65 28 29 } 		$a_00_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 43 61 6c 6c 42 79 4e 61 6d 65 28 } 		$a_00_2 = {22 54 45 47 22 2c } 		$a_00_3 = {22 6e 65 70 4f 22 } 		$a_00_4 = {22 41 2d 72 65 73 55 74 6e 65 67 } 	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*100) >=400
 
}