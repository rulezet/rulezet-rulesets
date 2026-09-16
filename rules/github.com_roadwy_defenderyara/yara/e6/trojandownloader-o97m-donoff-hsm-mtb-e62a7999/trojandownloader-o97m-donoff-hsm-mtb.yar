rule TrojanDownloader_O97M_Donoff_HSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 50 6a 6f 61 6f 31 35 37 38 2f 55 70 63 72 79 70 74 65 72 2f 6d 61 69 6e 2f 45 78 70 70 6c 6f 69 69 69 74 65 72 } 		$a_01_1 = {2e 52 75 6e 20 22 57 53 63 72 69 70 74 2e 65 78 65 20 51 6c 70 4b 78 2e 76 62 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}