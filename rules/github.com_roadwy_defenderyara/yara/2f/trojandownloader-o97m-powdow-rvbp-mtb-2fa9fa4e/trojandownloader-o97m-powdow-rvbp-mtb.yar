rule TrojanDownloader_O97M_Powdow_RVBP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 } 		$a_01_1 = {2d 6f 75 74 46 49 6c 45 20 6f 2e 65 78 65 20 20 20 3b 20 2e 5c 6f 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}