rule TrojanDownloader_O97M_Powdow_PD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 58 45 43 28 22 43 3a 5c 22 26 43 48 41 52 28 38 30 29 26 43 48 41 52 28 38 32 29 26 22 4f 47 52 41 4d 44 41 54 41 5c 61 2e 22 26 43 48 41 52 28 31 30 31 29 26 22 78 65 22 29 } 		$a_00_1 = {75 72 22 26 43 48 41 52 28 31 30 38 29 26 22 6d 6f 6e } 		$a_00_2 = {4a 4a 43 43 4a 4a } 		$a_00_3 = {43 48 41 52 28 31 30 34 29 26 22 74 74 70 3a 2f 2f 63 75 74 74 2e 6c 79 2f 75 68 6e 73 47 56 4b } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}