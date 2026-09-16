rule TrojanDownloader_O97M_Donoff_50{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 62 74 69 54 41 62 74 69 52 54 62 74 69 2d 70 62 74 69 72 4f 62 74 69 63 45 62 74 69 53 73 62 74 69 20 27 62 74 69 25 41 62 74 69 50 70 62 74 69 44 41 62 74 69 74 41 62 74 69 25 2e 62 74 69 65 78 62 74 69 65 27 62 74 69 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}