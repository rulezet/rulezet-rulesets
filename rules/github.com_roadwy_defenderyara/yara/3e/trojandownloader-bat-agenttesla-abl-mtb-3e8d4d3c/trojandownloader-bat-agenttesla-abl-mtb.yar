rule TrojanDownloader_BAT_AgentTesla_ABL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 0a 2b 07 28 ?? ?? ?? 06 2b eb 06 16 06 8e 69 28 ?? ?? ?? 0a 2b 07 90 0a 21 00 02 72 ?? ?? ?? 70 28 06 } 		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 		$a_01_2 = {52 65 76 65 72 73 65 } 	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}