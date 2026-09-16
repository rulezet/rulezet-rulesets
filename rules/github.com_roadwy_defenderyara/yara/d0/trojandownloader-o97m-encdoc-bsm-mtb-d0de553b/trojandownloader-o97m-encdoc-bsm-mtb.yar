rule TrojanDownloader_O97M_EncDoc_BSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 6f 73 6c 6f 62 69 6b 65 72 65 6e 74 61 6c 2e 6e 6f 2e 77 77 31 38 2e 6f 6e 6c 69 6e 65 34 75 2e 6e 6f 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 32 2f 75 70 73 2f 49 4d 47 30 30 31 32 30 34 37 34 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}