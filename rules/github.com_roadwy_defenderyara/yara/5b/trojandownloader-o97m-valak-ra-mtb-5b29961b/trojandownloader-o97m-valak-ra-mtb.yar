rule TrojanDownloader_O97M_Valak_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 42 5f 4e 61 6d 65 20 3d 20 22 72 54 22 } 		$a_01_1 = {22 72 65 67 73 76 72 22 20 26 20 33 32 20 26 20 22 20 22 } 		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_03_3 = {44 69 6d 20 ?? ?? 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c 0d 0a 90 1b 00 2e 65 78 65 63 20 6b 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}