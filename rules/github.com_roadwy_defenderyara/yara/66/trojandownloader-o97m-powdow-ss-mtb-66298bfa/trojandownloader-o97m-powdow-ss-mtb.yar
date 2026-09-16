rule TrojanDownloader_O97M_Powdow_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 6c 6b 6a 6c 6a 6b 6a 6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 72 76 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 6f 78 36 74 39 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}