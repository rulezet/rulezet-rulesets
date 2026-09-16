rule TrojanDownloader_Linux_Adnel_11{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 37 58 71 6d 36 68 4f 47 57 33 35 6c 4a 37 6c 4c 20 3d 20 48 52 35 4d 61 32 45 38 71 66 70 33 28 48 42 36 33 6c 72 38 7a 35 33 71 7a 77 38 6d 2c 20 52 77 6c 69 59 47 74 6d 6c 76 29 } 		$a_01_1 = {53 68 65 6c 6c 20 49 37 58 71 6d 36 68 4f 47 57 33 35 6c 4a 37 6c 4c 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}