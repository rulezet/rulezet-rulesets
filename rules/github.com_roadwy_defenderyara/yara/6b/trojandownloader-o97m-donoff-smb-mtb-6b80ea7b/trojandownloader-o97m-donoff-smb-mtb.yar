rule TrojanDownloader_O97M_Donoff_SMB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SMB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f 31 37 2f 43 6f 6e 73 6f 6c 65 41 70 70 31 38 2e 65 78 22 20 26 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}