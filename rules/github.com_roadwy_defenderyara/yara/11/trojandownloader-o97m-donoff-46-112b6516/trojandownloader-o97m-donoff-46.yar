rule TrojanDownloader_O97M_Donoff_46{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 [0-10] 28 [0-10] 28 22 32 35 36 20 32 36 33 20 32 35 37 20 32 33 38 20 32 35 36 20 32 36 32 20 32 36 33 20 32 33 38 20 32 35 37 20 32 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}