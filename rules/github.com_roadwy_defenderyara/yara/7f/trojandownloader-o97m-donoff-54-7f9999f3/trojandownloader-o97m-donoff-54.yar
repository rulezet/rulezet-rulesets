rule TrojanDownloader_O97M_Donoff_54{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 69 72 65 63 74 65 78 65 2e 63 6f 6d 2f 33 73 30 2f 70 74 6d 5f 68 65 6b 2e 65 78 65 } 		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 52 65 70 6c 61 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}