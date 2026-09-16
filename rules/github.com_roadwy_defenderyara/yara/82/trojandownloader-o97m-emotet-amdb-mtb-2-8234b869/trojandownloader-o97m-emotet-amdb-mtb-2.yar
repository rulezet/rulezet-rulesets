rule TrojanDownloader_O97M_Emotet_AMDB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 79 68 6a 6c 73 77 6c 65 2e 76 62 73 } 		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 75 67 68 6c 64 73 6b 62 68 6e 2e 62 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}