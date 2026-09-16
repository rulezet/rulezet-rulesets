rule TrojanDownloader_O97M_EncDoc_P_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.P!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 69 6e 65 78 65 75 70 6c 6f 61 64 2e 72 75 2f 34 35 34 37 6a 73 } 		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 6d 73 69 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}