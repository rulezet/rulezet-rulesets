rule TrojanDownloader_O97M_DBatLoader_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/DBatLoader.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 70 6c 70 6c 2c 66 61 6c 73 65 78 68 74 74 70 2e 73 65 6e 64 } 		$a_01_1 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}