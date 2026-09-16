rule Backdoor_BAT_Bladabindi_gen_T_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!T,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d0 1b 00 00 06 26 1b 0a 2b d0 04 03 61 1f 4b 59 45 01 00 00 00 04 00 00 00 17 } 		$a_01_1 = {05 04 61 1f 38 59 45 01 00 00 00 04 00 00 00 16 0a 2b bd } 		$a_01_2 = {05 04 61 1f 39 59 45 01 00 00 00 02 00 00 00 2b ef 00 02 03 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}