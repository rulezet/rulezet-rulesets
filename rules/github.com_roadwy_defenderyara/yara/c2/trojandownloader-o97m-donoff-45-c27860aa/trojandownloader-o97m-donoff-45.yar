rule TrojanDownloader_O97M_Donoff_45{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 41 74 56 32 6c 75 5a 47 39 33 55 33 52 35 62 47 } 		$a_01_1 = {55 67 53 47 6c 6b 5a 47 56 75 49 43 52 33 63 32 4e 79 61 58 42 30 49 44 30 67 62 6d 56 33 4c 57 39 69 61 6d 56 6a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}