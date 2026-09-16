rule TrojanDownloader_O97M_Obfuse_SA_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_01_1 = {55 52 4c 4d 4f 4e } 		$a_03_2 = {68 74 74 70 73 3a 2f 2f 61 70 65 72 66 6f 72 72 6d 69 6e 67 6e 65 78 74 79 6f 75 2e 78 79 7a 2f [0-07] 2f [0-03] 2e 64 6c 6c } 		$a_03_3 = {43 3a 5c 6b 66 55 6f 66 57 6a 5c [0-07] 5c [0-07] 2e 64 6c 6c 20 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}