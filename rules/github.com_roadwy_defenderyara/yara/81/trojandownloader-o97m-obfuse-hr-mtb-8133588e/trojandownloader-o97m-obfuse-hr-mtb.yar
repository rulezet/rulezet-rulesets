rule TrojanDownloader_O97M_Obfuse_HR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_03_1 = {31 39 35 2e 31 32 33 2e 32 34 31 2e 31 34 34 2f 61 70 69 2e 70 68 70 90 0a 1e 00 68 74 74 70 3a 2f 2f } 		$a_00_2 = {43 3a 5c 56 65 72 74 69 73 5c 4b 6f 74 73 5c 73 76 63 68 6f 73 74 } 		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}