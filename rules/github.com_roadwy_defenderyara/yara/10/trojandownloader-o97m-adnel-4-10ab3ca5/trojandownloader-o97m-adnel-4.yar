rule TrojanDownloader_O97M_Adnel_4{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 34 20 2b 20 [0-10] 20 2b 20 36 0d 0a 45 78 69 74 20 53 75 62 } 		$a_02_1 = {2d 20 39 37 20 2b 20 [0-15] 20 32 36 29 20 2b 20 39 37 29 0d 0a 45 6c 73 65 } 		$a_02_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 90 0a 4f 00 2f 2f 3a } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}