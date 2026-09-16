rule TrojanDownloader_O97M_Emotet_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 71 71 71 77 2f 61 61 61 73 2f 73 65 2e 68 74 6d 6c } 		$a_03_1 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f 90 05 03 05 28 61 2d 7a 29 2f 90 05 03 05 28 61 2d 7a 29 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}