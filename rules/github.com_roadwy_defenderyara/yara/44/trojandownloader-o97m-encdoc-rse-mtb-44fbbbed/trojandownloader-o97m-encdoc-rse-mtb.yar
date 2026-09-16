rule TrojanDownloader_O97M_EncDoc_RSE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6c 61 6e 6b 61 72 65 63 69 70 65 73 2e 63 6f 6d 2f 6d 61 67 65 73 2e 6a 70 27 20 20 2b 20 27 67 27 90 0a 30 00 63 75 72 4c 20 20 28 27 68 74 74 70 3a 2f 2f } 		$a_00_1 = {43 6d 44 2e 45 78 65 20 20 2f 43 20 70 6f 57 65 52 53 68 65 4c 4c 2e 45 58 65 20 20 2d 65 78 20 42 59 50 41 73 53 20 2d 4e 6f 50 20 2d 77 20 31 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}