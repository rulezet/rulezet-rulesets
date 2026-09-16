rule Backdoor_Win32_Vawtrak_A{
	meta:
		description = "Backdoor:Win32/Vawtrak.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 6a 1a 59 f7 f1 83 c2 61 66 89 14 7b 47 3b fe 72 } 		$a_01_1 = {33 d2 6a 1a 59 f7 f1 80 c2 61 88 14 1f 47 3b fe 72 } 		$a_01_2 = {80 38 3a 75 03 50 eb 18 8b 45 f8 ff b0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}