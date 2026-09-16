rule TrojanDownloader_O97M_Emotet_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 72 74 79 75 73 64 6a 2e 62 61 74 } 		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 75 79 6c 63 73 65 6b 6e 2e 62 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}