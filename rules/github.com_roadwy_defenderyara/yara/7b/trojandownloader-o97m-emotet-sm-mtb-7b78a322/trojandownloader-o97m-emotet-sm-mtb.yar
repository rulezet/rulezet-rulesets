rule TrojanDownloader_O97M_Emotet_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 7a 78 2f 63 76 2f 66 65 2e 68 74 6d 6c } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}