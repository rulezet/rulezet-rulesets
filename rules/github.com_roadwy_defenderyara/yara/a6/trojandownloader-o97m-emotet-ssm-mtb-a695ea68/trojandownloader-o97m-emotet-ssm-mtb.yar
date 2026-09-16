rule TrojanDownloader_O97M_Emotet_SSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 47 67 41 64 41 42 30 41 48 41 41 4f 67 41 76 41 43 38 41 63 67 42 72 41 47 55 41 5a 51 42 77 41 47 55 41 63 67 42 31 41 47 45 41 4c 67 42 6a 41 47 38 41 62 51 41 76 41 47 6b 41 62 67 42 6a 41 47 77 41 64 51 42 6b 41 47 55 41 4c 77 42 47 41 46 67 41 51 67 42 7a 41 46 59 41 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}