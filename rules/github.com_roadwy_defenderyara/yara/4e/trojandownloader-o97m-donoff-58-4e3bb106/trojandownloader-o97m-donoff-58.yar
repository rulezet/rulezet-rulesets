rule TrojanDownloader_O97M_Donoff_58{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 56 68 59 74 74 64 32 70 59 3a 59 2f 50 2f 41 61 6b 50 50 73 6f 32 63 41 69 41 59 61 59 6c 2e 50 69 48 32 6e 2f 59 73 32 79 32 73 32 32 74 76 65 6d 56 41 2f 6c 56 32 6f 76 67 73 56 2f 48 41 78 2e 56 56 70 76 68 70 48 41 3f 59 74 69 32 59 74 6c 50 64 65 48 3d 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}