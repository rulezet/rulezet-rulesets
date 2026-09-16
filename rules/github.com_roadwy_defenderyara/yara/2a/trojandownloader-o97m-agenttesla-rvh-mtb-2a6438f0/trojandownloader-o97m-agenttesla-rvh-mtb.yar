rule TrojanDownloader_O97M_AgentTesla_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 73 68 65 6c 6c 21 28 6d 6f 6e 69 74 6f 72 29 65 6e 64 66 75 6e 63 74 69 6f 6e } 		$a_01_1 = {75 73 65 74 77 6f 31 2e 63 6f 6d 6d 61 6e 64 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 78 74 3d 78 31 65 6e 64 66 75 6e 63 74 69 6f 6e } 		$a_01_2 = {6f 6e 65 3d 67 68 74 2e 65 6c 65 70 68 61 6e 74 5f 2b 6c 6c 74 2e 6c 6f 72 61 74 77 6f 3d 6c 6c 74 2e 6b 2b 6c 6c 74 2e 74 5f 2b 6c 6c 74 2e 78 74 74 68 72 65 65 3d 6f 6e 65 5f 2b 74 77 6f } 		$a_01_3 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}