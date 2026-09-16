rule TrojanDownloader_O97M_Emotet_AMDB_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 66 65 2f 66 2e 68 74 6d 6c } 		$a_01_1 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 71 77 2f 61 73 2f 73 65 2e 68 74 6d 6c } 		$a_01_2 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 7a 71 71 77 2f 7a 61 61 73 2f 66 65 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}