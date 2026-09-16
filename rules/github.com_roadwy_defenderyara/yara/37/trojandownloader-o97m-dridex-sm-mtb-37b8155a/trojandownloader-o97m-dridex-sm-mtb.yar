rule TrojanDownloader_O97M_Dridex_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 65 75 72 6f 2d 6f 66 66 69 63 65 2e 6e 65 74 2f 41 77 49 33 75 77 69 77 75 55 36 2e 70 68 70 } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 6c 61 6d 69 72 61 67 65 72 65 63 65 70 74 69 6f 6e 2e 63 6f 6d 2e 61 75 2f 41 42 73 38 64 4a 32 5a 4a 33 6a 67 76 30 6e 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}