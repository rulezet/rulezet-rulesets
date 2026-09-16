rule TrojanDownloader_O97M_Donoff_59{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 5b 72 6b 72 2e 21 67 29 61 72 21 76 21 79 5b 70 2f 66 72 67 29 6e 79 63 21 7a 21 72 29 67 2f 72 5d 74 21 6e 7a 5b 5d 76 29 2f 7a 5d 5d 62 70 2e 61 21 5b 62 5d 71 61 62 79 72 29 61 21 76 79 61 29 21 62 21 71 62 62 5d 73 5b 2f 2f 21 29 3a 63 67 5b 5d 67 21 75 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}