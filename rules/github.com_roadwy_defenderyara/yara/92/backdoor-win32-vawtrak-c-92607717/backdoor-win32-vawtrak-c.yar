rule Backdoor_Win32_Vawtrak_C{
	meta:
		description = "Backdoor:Win32/Vawtrak.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 03 59 33 d2 f7 f1 6a 00 5f 8b f2 83 c6 06 74 } 		$a_01_1 = {81 3e 41 50 33 32 75 72 8b 46 08 83 c1 e8 3b c1 75 68 83 7e 10 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}