rule TrojanDownloader_O97M_EncDoc_PSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 68 77 73 65 31 } 		$a_01_1 = {52 47 68 6a 67 6a 74 31 } 		$a_01_2 = {52 47 68 6a 67 6a 74 32 } 		$a_01_3 = {54 54 47 45 48 45 48 45 48 46 48 44 47 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}