rule TrojanDownloader_O97M_Donoff_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 70 6a 2e 31 63 6e 33 72 6d 33 32 39 5f 70 2f 74 65 6e 2e 70 6f 74 34 70 6f 74 2e 61 2f 2f 3a 73 70 74 74 68 } 		$a_03_1 = {53 74 72 52 65 76 65 72 73 65 28 [0-03] 65 78 65 2e [0-14] 5c 61 74 61 44 6d 61 72 67 6f 72 50 5c 3a 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}