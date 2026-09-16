rule TrojanDownloader_O97M_Donoff_SM_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 65 67 61 76 75 2e 63 6f 6d 2f 37 32 38 30 2d 32 38 31 32 2d 33 33 33 32 2e 64 6c 6c } 		$a_01_1 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}