rule TrojanDownloader_Linux_Adnel_3{
	meta:
		description = "TrojanDownloader:Linux/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 49 46 45 78 55 79 41 70 59 7a 73 20 3d 20 56 48 65 34 31 55 28 4c 53 65 78 65 41 58 57 35 50 49 2c 20 53 72 61 31 68 29 } 		$a_01_1 = {53 68 65 6c 6c 20 43 49 46 45 78 55 79 41 70 59 7a 73 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}