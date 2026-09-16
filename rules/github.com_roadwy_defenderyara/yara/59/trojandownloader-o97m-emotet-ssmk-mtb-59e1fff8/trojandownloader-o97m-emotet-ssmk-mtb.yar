rule TrojanDownloader_O97M_Emotet_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 68 65 6e 72 79 73 66 72 65 73 68 72 6f 61 73 74 2e 63 6f 6d 2f 4f 65 76 49 37 59 79 30 69 36 59 53 68 78 46 6c 2f } 		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6a 61 78 6d 61 74 74 65 72 73 2e 63 6f 6d 2f 63 37 67 38 74 2f 6e 6e 7a 4a 4a 31 72 4b 46 44 32 50 2f } 		$a_01_2 = {68 74 74 70 3a 2f 2f 61 6f 70 64 61 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 35 6f 54 41 56 4a 79 6a 44 46 4f 6c 6c 58 32 75 45 2f } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}