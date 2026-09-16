rule TrojanDownloader_O97M_Donoff_24{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 69 59 58 52 68 64 47 45 79 4d 44 45 31 4c 6d 4e 76 62 53 39 68 59 6d 4d 76 5a 53 35 6b 59 58 51 3d 22 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}