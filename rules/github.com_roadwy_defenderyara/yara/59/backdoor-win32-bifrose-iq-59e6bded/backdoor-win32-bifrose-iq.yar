rule Backdoor_Win32_Bifrose_IQ{
	meta:
		description = "Backdoor:Win32/Bifrose.IQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 14 c7 00 68 00 00 00 90 90 a1 ?? ?? ?? ?? c7 40 01 ?? ?? ?? ?? 90 90 ff d6 } 		$a_01_1 = {80 34 03 f3 ff d7 50 ff d6 8b 45 fc 80 34 03 c2 ff d7 50 ff d6 8b 45 fc 80 34 03 d4 43 3b 5d f8 72 d6 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}