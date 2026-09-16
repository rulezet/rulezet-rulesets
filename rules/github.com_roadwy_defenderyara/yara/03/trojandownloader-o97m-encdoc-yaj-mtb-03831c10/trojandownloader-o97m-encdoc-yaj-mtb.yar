rule TrojanDownloader_O97M_EncDoc_YAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 75 65 62 6c 65 73 6d 61 70 6c 65 2e 63 6f 6d 2e 6d 78 2f 31 39 2e 67 69 66 } 		$a_01_1 = {43 3a 5c 57 45 72 74 75 5c 52 65 74 65 72 64 5c 73 7a 76 6d 68 65 67 75 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}