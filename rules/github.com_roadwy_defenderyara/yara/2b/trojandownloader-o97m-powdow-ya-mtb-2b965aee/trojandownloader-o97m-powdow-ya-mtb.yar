rule TrojanDownloader_O97M_PowDow_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/PowDow.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 43 41 41 61 51 42 6c 41 48 67 41 4b 41 41 6b } 		$a_01_1 = {52 41 42 76 41 48 63 41 62 67 42 73 41 47 38 41 59 51 42 6b 41 46 4d 41 64 41 42 79 41 47 6b 41 62 67 42 6e 41 43 67 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}