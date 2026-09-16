rule TrojanDownloader_Linux_Adnel{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 69 70 68 6f 6e 65 74 65 63 68 69 65 2e 63 6f 6d 2f 77 7a 2f 63 61 6e 2f 63 61 77 69 6e 6e } 		$a_01_1 = {22 5c 53 4f 6b 66 64 73 73 64 2e 69 6e 69 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}