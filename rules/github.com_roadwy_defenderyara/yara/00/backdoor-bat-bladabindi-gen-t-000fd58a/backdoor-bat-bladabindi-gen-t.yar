rule Backdoor_BAT_Bladabindi_gen_T{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!T,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 02 61 1f 17 59 45 01 00 00 00 04 00 00 00 16 } 		$a_01_1 = {04 03 61 1f 43 59 45 01 00 00 00 04 00 00 00 1c } 		$a_01_2 = {20 7b 30 00 00 9d 06 1a 20 34 1d 00 00 9d 06 1b 20 97 1f 00 00 9d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=11
 
}