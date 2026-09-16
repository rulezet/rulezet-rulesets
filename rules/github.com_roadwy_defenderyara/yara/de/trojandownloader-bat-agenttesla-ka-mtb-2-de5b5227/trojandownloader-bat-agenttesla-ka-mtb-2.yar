rule TrojanDownloader_BAT_AgentTesla_KA_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 ?? ?? ?? 70 73 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 0b 07 8e } 		$a_01_1 = {48 74 74 70 43 6c 69 65 6e 74 } 		$a_01_2 = {41 64 64 52 61 6e 67 65 } 		$a_01_3 = {52 65 76 65 72 73 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}