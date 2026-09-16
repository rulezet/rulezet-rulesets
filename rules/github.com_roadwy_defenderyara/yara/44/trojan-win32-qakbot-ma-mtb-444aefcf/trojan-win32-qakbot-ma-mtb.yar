rule Trojan_Win32_Qakbot_MA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4c 55 61 37 } 		$a_01_1 = {50 48 59 53 54 32 4a 58 33 } 		$a_01_2 = {55 59 68 34 31 75 62 } 		$a_01_3 = {56 65 6d 66 61 34 57 4e } 		$a_01_4 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=13
 
}