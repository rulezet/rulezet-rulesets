rule TrojanDownloader_O97M_Donoff_PC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PC,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 2e 56 61 6c 75 65 29 [0-10] 45 6e 64 20 53 75 62 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}