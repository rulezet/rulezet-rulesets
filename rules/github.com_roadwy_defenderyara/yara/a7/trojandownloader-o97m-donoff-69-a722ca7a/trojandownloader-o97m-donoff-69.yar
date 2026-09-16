rule TrojanDownloader_O97M_Donoff_69{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 6d 65 72 69 63 69 75 6d 20 3d 20 65 74 65 72 63 6f 72 61 6c 20 2b 20 4c 65 66 74 28 22 5c 65 65 6c 65 70 68 61 6e 74 6f 70 75 73 22 2c 20 32 29 20 2b 20 55 63 61 73 65 28 22 78 70 49 72 22 29 20 2b 20 52 69 67 68 74 28 22 64 65 78 74 65 72 69 74 79 61 74 6f 72 79 2e 65 78 65 22 2c 20 39 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}