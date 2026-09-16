rule TrojanDownloader_Linux_Donoff_2{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 42 71 74 66 74 70 69 71 3a 2f 52 66 2f 68 42 66 70 73 71 61 71 66 7a 2e 69 69 63 71 6f 71 6d 2f 71 69 73 35 79 73 69 66 74 35 65 6d 42 52 2f 71 63 71 61 63 56 42 68 35 65 35 2f 69 77 71 6f 72 52 56 64 42 2e 65 35 66 78 65 52 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}