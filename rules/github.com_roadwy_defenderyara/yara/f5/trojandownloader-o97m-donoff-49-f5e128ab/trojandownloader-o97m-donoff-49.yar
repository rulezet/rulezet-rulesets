rule TrojanDownloader_O97M_Donoff_49{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 4f 4f 48 69 63 72 6f 52 4f 4f 4f 48 6f 66 74 2e 58 52 4f 4f 48 4c 48 54 54 50 52 4f 4f 4f 4f 48 41 64 6f 64 62 2e 52 4f 4f 4f 48 74 72 52 4f 48 61 52 4f 4f 48 52 4f 4f 4f 4f 48 52 4f 4f 4f 48 68 52 4f 48 6c 6c 2e 41 70 70 6c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}