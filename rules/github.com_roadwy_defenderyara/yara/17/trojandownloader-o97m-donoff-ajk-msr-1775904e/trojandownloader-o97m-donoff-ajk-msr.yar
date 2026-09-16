rule TrojanDownloader_O97M_Donoff_AJK_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 74 70 22 20 2b 20 22 3a 2f 22 20 2b 20 22 2f 64 65 66 2e 6e 69 6d 65 2e 78 79 7a 3a 32 30 39 35 2f 73 6c 69 6e 67 2f 72 77 63 6f 72 65 2e 65 78 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 20 25 74 6d 70 25 2f 74 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}