rule TrojanDownloader_O97M_Donoff_KSH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.KSH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 6d 70 2f 61 67 6b 61 6f 73 6b 61 73 66 6b 73 61 6b 64 61 6d 73 6b 64 6f 6b 61 73 64 6b 61 73 6f 64 6b 61 6f 73 } 		$a_00_1 = {6d 73 67 62 6f 78 22 66 69 6c 65 69 73 63 6f 72 72 75 70 74 22 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 6d 61 69 6e 65 6e 64 73 75 62 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}