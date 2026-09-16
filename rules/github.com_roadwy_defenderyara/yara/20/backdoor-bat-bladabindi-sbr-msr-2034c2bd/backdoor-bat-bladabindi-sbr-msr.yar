rule Backdoor_BAT_Bladabindi_SBR_MSR{
	meta:
		description = "Backdoor:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 26 28 [0-02] 00 06 28 08 00 00 0a 72 [0-02] 00 70 28 [0-02] 00 06 28 08 00 00 0a 28 10 00 00 0a 2a } 		$a_03_1 = {0a 06 26 28 [0-02] 00 06 28 07 00 00 0a 0b 28 [0-02] 00 06 28 08 00 00 0a 0c 18 0d 18 8d 01 00 00 01 13 04 11 04 16 28 [0-02] 00 06 a2 07 08 09 11 04 28 09 00 00 0a 2a } 		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}