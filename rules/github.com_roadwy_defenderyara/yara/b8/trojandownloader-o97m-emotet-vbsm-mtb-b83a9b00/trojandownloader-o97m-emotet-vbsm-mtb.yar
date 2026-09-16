rule TrojanDownloader_O97M_Emotet_VBSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VBSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 22 26 22 31 2f 30 63 22 26 22 4a 70 22 26 22 55 4a 22 26 22 58 42 22 26 22 68 75 22 26 22 42 61 22 26 22 4d 64 22 26 22 56 57 22 26 22 51 66 2f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}