rule TrojanDownloader_O97M_Bartallex{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 37 72 76 6d 6e 62 [0-28] 2f 61 66 2f 37 72 76 6d 6e 62 [0-28] 2f 61 66 2f 37 72 76 6d 6e 62 [0-28] 2f 37 72 76 6d 6e 62 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}