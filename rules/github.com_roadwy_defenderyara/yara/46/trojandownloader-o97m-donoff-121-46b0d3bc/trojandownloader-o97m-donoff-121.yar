rule TrojanDownloader_O97M_Donoff_121{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 6d 5a 6f 78 59 39 33 38 6b 64 57 73 5a 6f 78 59 39 33 38 6b 64 57 73 5a 6f 78 59 39 33 38 6b 64 57 63 5a 6f 78 59 39 33 38 6b 64 57 72 5a 6f 78 59 39 33 38 6b 64 57 69 5a 6f 78 59 39 33 38 6b 64 57 70 5a 6f 78 59 39 33 38 6b 64 57 74 5a 6f 78 59 39 33 38 6b 64 57 63 5a 6f 78 59 39 33 38 6b 64 57 6f 5a 6f 78 59 39 33 38 6b 64 57 6e 5a 6f 78 59 39 33 38 6b 64 57 74 5a 6f 78 59 39 33 38 6b 64 57 72 5a 6f 78 59 39 33 38 6b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}