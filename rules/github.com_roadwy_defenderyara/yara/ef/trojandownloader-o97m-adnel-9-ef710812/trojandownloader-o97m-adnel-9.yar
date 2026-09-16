rule TrojanDownloader_O97M_Adnel_9{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 54 59 46 69 64 73 66 66 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 68 73 64 69 75 66 67 68 62 6a 6b 62 48 4a 46 55 48 6b 6a 62 73 64 68 62 66 64 73 6b 66 2e 54 65 78 74 42 6f 78 32 } 		$a_01_1 = {70 6a 49 4f 48 64 73 66 63 20 3d 20 68 73 64 69 75 66 67 68 62 6a 6b 62 48 4a 46 55 48 6b 6a 62 73 64 68 62 66 64 73 6b 66 2e 54 65 78 74 42 6f 78 31 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}