rule TrojanDownloader_O97M_Donoff_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e } 		$a_01_1 = {76 61 72 30 20 3d 20 22 6d 73 48 54 61 20 68 74 74 70 73 3a 2f 2f 70 70 61 6d 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f 70 61 6e 64 65 2e 68 74 6d 6c 22 } 		$a_01_2 = {56 61 52 20 3d 20 76 61 72 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}