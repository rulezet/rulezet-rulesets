rule TrojanDownloader_O97M_Adnel_2{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 57 6f 6c 49 64 44 75 } 		$a_01_1 = {c6 c4 d3 8c 78 af } 		$a_01_2 = {53 68 65 6c 6c 20 } 		$a_01_3 = {2c 20 76 62 48 69 64 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}