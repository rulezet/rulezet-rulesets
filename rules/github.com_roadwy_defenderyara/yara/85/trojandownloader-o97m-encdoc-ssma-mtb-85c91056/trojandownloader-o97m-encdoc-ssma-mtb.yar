rule TrojanDownloader_O97M_EncDoc_SSMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f 6f 6f 2e 68 74 6d 6c } 		$a_01_1 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f 61 61 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}