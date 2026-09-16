rule TrojanDownloader_O97M_AgentTesla_BPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6e 70 6f 77 65 72 31 20 3d 20 6d 61 6e 31 20 2b 20 6d 61 6e 32 20 2b 20 6d 61 6e 33 } 		$a_01_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6d 61 6e 70 6f 77 65 72 33 29 29 } 		$a_01_2 = {6d 61 6e 32 20 3d 20 69 63 65 63 72 65 61 6d 31 2e 6a 61 63 6b 31 2e 54 61 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}