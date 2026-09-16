rule TrojanDownloader_O97M_AgentTesla_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 5e 69 5e 4e 5e 67 5e 2e 5e 65 5e 58 5e 45 } 		$a_01_1 = {5e 68 5e 74 5e 74 5e 70 5e 73 5e 3a 5e 2f 5e 2f 5e 63 5e 61 5e 6e 5e 61 5e 64 5e 61 5e 63 5e 69 5e 67 5e 61 5e 72 5e 73 5e 75 5e 70 5e 70 5e 6c 5e 69 5e 65 5e 73 5e 2e 5e 63 5e 6f 5e 6d 5e 2f 5e 77 5e 70 5e 2d 5e 63 5e 6f 5e 6e 5e 74 5e 65 5e 6e 5e 74 5e 2f 5e 75 5e 70 5e 6c 5e 6f 5e 61 5e 64 5e 73 5e 2f 5e 32 5e 30 5e 31 5e 38 5e 2f 5e 30 5e 35 5e 2f 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2f 5e 61 5e 6e 5e 6f 5e 2e 5e 65 5e 78 5e 65 } 		$a_01_2 = {25 54 45 4d 50 25 5e 5c 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2e 5e 65 5e 78 5e 65 } 		$a_01_3 = {73 5e 74 5e 61 5e 72 5e 74 5e 20 20 20 5e 20 20 20 5e 20 20 20 25 54 45 4d 50 25 5e 5c 5e 66 5e 69 5e 6c 5e 65 5e 73 5e 2e 5e 65 5e 78 5e 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}