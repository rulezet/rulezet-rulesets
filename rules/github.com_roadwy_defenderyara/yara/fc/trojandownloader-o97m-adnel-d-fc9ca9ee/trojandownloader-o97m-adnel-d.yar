rule TrojanDownloader_O97M_Adnel_D{
	meta:
		description = "TrojanDownloader:O97M/Adnel.D,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {2b 20 22 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 6f 49 55 49 59 67 73 61 64 66 64 73 76 64 76 73 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 54 45 22 20 2b 20 22 4d 50 22 29 20 26 20 22 5c 64 73 66 66 66 66 64 2e 76 62 73 22 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}