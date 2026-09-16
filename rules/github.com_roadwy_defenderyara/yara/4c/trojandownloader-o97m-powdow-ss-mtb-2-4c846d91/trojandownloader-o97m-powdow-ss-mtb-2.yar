rule TrojanDownloader_O97M_Powdow_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f 6a 6f 72 6e 61 6c 64 61 63 69 64 61 64 65 2e 73 74 6f 72 65 2f } 		$a_01_1 = {53 68 65 6c 6c } 		$a_01_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}