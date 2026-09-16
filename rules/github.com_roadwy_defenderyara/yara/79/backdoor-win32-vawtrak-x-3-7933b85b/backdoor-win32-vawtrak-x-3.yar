rule Backdoor_Win32_Vawtrak_X_3{
	meta:
		description = "Backdoor:Win32/Vawtrak.X,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 } 		$a_01_1 = {7e 00 25 00 30 00 2e 00 38 00 78 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=100
 
}