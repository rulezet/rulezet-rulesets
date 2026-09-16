rule TrojanDownloader_Linux_Adnel_C{
	meta:
		description = "TrojanDownloader:Linux/Adnel.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {67 65 22 20 26 20 22 2e 22 20 26 20 22 74 74 2f } 		$a_00_1 = {46 75 63 6b 69 6e 67 53 74 72 69 6e 67 } 		$a_00_2 = {50 72 6f 75 64 74 6f 42 65 63 6f 6d 65 61 4e 65 70 61 6c 69 52 65 76 65 72 73 65 45 6e 67 69 6e 65 65 72 28 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}