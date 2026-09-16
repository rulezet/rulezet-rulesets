rule TrojanDownloader_Linux_Adnel_2{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 68 70 67 2e 73 65 2f 74 6d 70 2f 6c 6e 73 2e 74 78 74 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 73 75 6e 64 73 76 61 6c 6c 73 72 6b 2e 6e 75 2f 74 6d 70 2f 6c 6e 73 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}