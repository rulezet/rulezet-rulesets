rule TrojanDownloader_O97M_Emotet_ASS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ASS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 69 73 67 75 76 65 6e 6c 69 67 69 62 75 72 61 64 61 2e 63 6f 6d 2f 78 63 67 2f 75 5a 53 55 2f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}