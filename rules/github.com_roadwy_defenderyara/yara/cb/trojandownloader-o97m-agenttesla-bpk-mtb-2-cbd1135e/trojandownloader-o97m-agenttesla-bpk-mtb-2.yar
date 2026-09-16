rule TrojanDownloader_O97M_AgentTesla_BPK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6b 2e 6d 79 76 61 6c 75 65 20 2b 20 6b 2e 6d 79 76 61 6c 75 65 32 } 		$a_01_1 = {74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 2e 6a 2e 6d 70 2f 61 73 64 61 6b 73 64 6a 71 77 6f 64 64 61 73 6b 64 61 6a 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}