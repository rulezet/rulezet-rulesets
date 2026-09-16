rule TrojanDownloader_O97M_Donoff_89{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 5b 51 2f 75 69 6d 67 73 5d 6f 67 63 45 6d 61 51 45 67 5b 52 79 3b 61 63 75 68 67 63 75 52 73 69 61 6c 69 75 68 68 61 69 45 73 2f 6c } 		$a_01_1 = {69 69 6b 73 76 6f 72 61 6d 61 54 20 3d 20 6d 61 73 6b 6f 66 6f 72 6f 73 28 49 6e 74 28 28 63 6e 31 32 33 34 35 36 20 2a 20 52 6e 64 28 29 29 20 2b 20 6b 69 74 74 79 6a 61 72 65 64 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}