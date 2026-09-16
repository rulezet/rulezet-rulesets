rule TrojanDownloader_BAT_Agent_A_AMTB{
	meta:
		description = "TrojanDownloader:BAT/Agent.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {48 61 63 6b 20 46 72 65 65 20 73 68 6f 70 } 		$a_80_1 = {53 76 20 64 72 20 76 30 2e 35 2e 70 64 62 } 		$a_80_2 = {68 74 74 70 3a 2f 2f 6b 69 63 68 68 6f 61 74 6b 65 79 2e 6f 6e 6c 69 6e 65 2f } 		$a_80_3 = {68 74 74 70 3a 2f 2f 64 61 6e 67 6b 79 6e 69 63 6b 2e 6f 6e 6c 69 6e 65 2f } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}