rule TrojanDownloader_O97M_Adnel_5{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 70 49 76 64 6d 50 74 46 77 72 4b 4f 69 20 3d 20 75 65 5a 72 58 6e 48 44 28 22 70 69 70 2e 70 6e 74 71 71 7a 2f 64 70 72 6c 78 74 2f 64 70 6f 66 77 6e 79 74 2d 61 68 2f 78 7a 6e 2e 32 31 74 64 63 6c 6e 2e 68 68 68 2f 2f 3a 61 65 65 73 22 2c 20 31 35 29 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}