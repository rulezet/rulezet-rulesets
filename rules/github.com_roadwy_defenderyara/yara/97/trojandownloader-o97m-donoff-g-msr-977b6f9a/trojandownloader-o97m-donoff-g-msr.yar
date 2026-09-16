rule TrojanDownloader_O97M_Donoff_G_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 76 4d 59 56 62 22 29 2e 43 65 6c 6c 73 28 31 33 34 2c 20 38 29 2e 56 61 6c 75 65 } 		$a_01_1 = {53 68 65 6c 6c 20 4d 6f 68 61 69 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}