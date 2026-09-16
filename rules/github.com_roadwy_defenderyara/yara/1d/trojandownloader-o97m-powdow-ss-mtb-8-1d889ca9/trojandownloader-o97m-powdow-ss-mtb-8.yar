rule TrojanDownloader_O97M_Powdow_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 22 20 2b 20 22 2e 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 22 20 2b 20 22 2f 22 20 2b 20 22 64 68 67 6a 6b 73 61 68 64 73 61 22 20 2b 20 22 74 77 69 65 71 62 64 68 73 73 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}