rule TrojanDownloader_O97M_Emotet_RP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_03_1 = {5c 64 78 67 78 65 [0-02] 2e 6f 63 78 } 	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}