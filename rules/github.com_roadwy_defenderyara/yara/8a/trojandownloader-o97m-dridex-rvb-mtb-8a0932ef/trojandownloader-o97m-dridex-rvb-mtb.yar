rule TrojanDownloader_O97M_Dridex_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 46 6a 45 4b 56 4f 54 72 47 4d 66 43 70 61 45 66 50 54 79 2e 72 74 66 22 } 		$a_03_1 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-19] 2e 72 74 66 22 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}