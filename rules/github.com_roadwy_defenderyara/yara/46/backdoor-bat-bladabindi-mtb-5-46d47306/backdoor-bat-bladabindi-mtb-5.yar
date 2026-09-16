rule Backdoor_BAT_Bladabindi_MTB_5{
	meta:
		description = "Backdoor:BAT/Bladabindi!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 6d 0a 00 70 18 18 8d 25 00 00 01 25 16 08 8c 0d 00 00 01 a2 25 17 11 04 8c 0d 00 00 01 a2 28 94 00 00 0a a5 0a 00 00 01 13 05 11 05 16 16 16 16 } 		$a_01_1 = {72 7f 0a 00 70 18 16 8d 25 00 00 01 28 94 00 00 0a a5 64 00 00 01 6f 97 00 00 0a 00 06 11 05 8c 0a 00 00 01 72 83 0a 00 70 18 16 8d 25 00 00 01 28 94 00 00 0a a5 64 00 00 01 6f 97 00 00 0a 00 06 11 05 8c 0a 00 00 01 72 87 0a 00 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}