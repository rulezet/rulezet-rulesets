rule TrojanDownloader_O97M_Emotet_BOP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f 73 73 2f 68 68 2e 68 74 6d 6c 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}