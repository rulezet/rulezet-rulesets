rule TrojanDownloader_O97M_AgentTesla_RVA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 73 68 65 6c 6c 21 28 74 65 78 74 66 69 6c 65 73 74 75 66 66 6f 6e 6c 79 29 65 6e 64 66 75 6e 63 74 69 6f 6e } 		$a_01_1 = {3d 6f 70 65 72 61 2e 78 2b 6f 70 65 72 61 2e 79 2b 74 65 78 74 66 69 6c 65 66 6f 72 79 6f 75 2e 7a 2b 74 65 78 74 66 69 6c 65 66 6f 72 79 6f 75 2e 64 2b 68 69 2e 6f 70 65 6e 6d 61 72 6b 65 74 2b 68 69 2e 78 78 78 2b 68 69 2e 6b 2b 68 69 2e 74 } 		$a_01_2 = {74 65 78 74 66 69 6c 65 73 74 75 66 66 2e 6d 6f 73 75 66 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e } 		$a_01_3 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}