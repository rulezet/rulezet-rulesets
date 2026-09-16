rule TrojanDownloader_O97M_Adnel_3{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 69 20 20 25 54 45 20 4d 50 25 20 5c 5c 22 2e 73 70 6c 69 74 28 22 20 22 29 3b } 		$a_01_1 = {20 2e 65 20 78 65 20 47 20 45 54 22 29 2e 73 70 6c 69 74 28 22 20 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}