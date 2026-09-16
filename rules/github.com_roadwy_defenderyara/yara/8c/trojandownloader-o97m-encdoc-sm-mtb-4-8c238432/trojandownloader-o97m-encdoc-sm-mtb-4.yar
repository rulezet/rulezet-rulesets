rule TrojanDownloader_O97M_EncDoc_SM_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 76 61 6c 28 27 7d 4b 4b 29 4b 4b 22 4b 4b 31 4b 4b 36 4b 4b 31 4b 4b 2e 4b 4b 32 4b 4b 32 4b 4b 32 4b 4b 2e 4b 4b 39 4b 4b 38 4b 4b 31 4b 4b 2e 4b 4b 35 4b 4b 2f 4b 4b 2f 4b 4b 3a 4b 4b 70 4b 4b 74 4b 4b 74 4b 4b 68 4b 4b 22 4b 4b 28 4b 4b 74 4b 4b 63 4b 4b 75 4b 4b 64 4b 4b 6f 4b 4b 72 4b 4b 50 4b 4b 6c 4b 4b 6c 4b 4b 61 4b 4b 74 4b 4b 73 4b 4b 6e 4b 4b 49 4b 4b 3b 4b 4b 32 4b 4b 3d 4b 4b 6c 4b 4b 65 4b 4b 76 4b 4b 65 4b 4b 4c 4b 4b 49 4b 4b 55 4b 4b 7b 4b 4b 29 4b 4b 29 4b 4b 22 4b 4b 72 4b 4b 65 4b 4b 6c 4b 4b 6c 4b 4b 61 4b 4b 74 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}