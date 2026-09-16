rule Backdoor_BAT_Bladabindi_SBR_MSR_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0b 00 00 04 28 20 00 00 0a 72 ?? 00 00 70 7e 0a 00 00 04 28 21 00 00 0a 0b 28 04 00 00 06 6f 22 00 00 0a 07 6f 23 00 00 0a } 		$a_03_1 = {20 d0 07 00 00 28 2f 00 00 0a 1f 1c 28 5a 00 00 0a 72 ?? 03 00 70 28 1e 00 00 0a 80 13 00 00 04 7e 13 00 00 04 72 ?? 03 00 70 28 1e 00 00 0a 28 55 00 00 0a 7e 0e 00 00 04 72 ?? 03 00 70 7e 0c 00 00 04 72 ?? 00 00 70 28 21 00 00 0a 6f 27 00 00 06 de 2c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}