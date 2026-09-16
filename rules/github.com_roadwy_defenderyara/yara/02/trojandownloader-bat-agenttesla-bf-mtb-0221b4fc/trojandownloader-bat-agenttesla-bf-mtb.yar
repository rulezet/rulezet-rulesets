rule TrojanDownloader_BAT_AgentTesla_BF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 00 30 00 37 00 2e 00 31 00 37 00 32 00 2e 00 31 00 33 00 2e 00 31 00 35 00 34 00 } 		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}