rule Backdoor_BAT_Bladabindi_GA_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 16 73 ?? ?? ?? 0a 0c 1a 8d ?? ?? ?? 01 0d 07 07 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 00 07 09 16 1a 6f ?? ?? ?? 0a 26 09 16 28 ?? ?? ?? 0a 13 04 07 16 6a 6f ?? ?? ?? 0a 00 11 04 17 da 17 d6 17 da 17 d6 17 da 17 d6 8d ?? ?? ?? 01 13 05 08 11 05 16 11 04 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 00 11 05 0a 2b 00 06 2a } 		$a_80_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } 		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=10
 
}