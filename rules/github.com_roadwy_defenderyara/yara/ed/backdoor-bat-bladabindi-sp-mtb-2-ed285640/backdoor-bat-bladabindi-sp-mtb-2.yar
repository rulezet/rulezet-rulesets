rule Backdoor_BAT_Bladabindi_SP_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 65 61 36 63 63 36 64 2d 30 36 33 65 2d 34 33 63 66 2d 39 36 63 65 2d 62 33 65 63 31 62 37 30 37 62 63 35 } 		$a_01_1 = {61 73 64 6a 4a 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {45 62 56 6b 39 64 4d 57 76 6f 64 73 75 30 46 67 5a 52 2e 4e 6d 55 52 74 73 5a 48 34 4e 50 4e 47 5a 50 53 42 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}