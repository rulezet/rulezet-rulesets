rule Trojan_Win32_ShellCodeRunner_KK_MTB_2{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 8c 2c 03 44 24 0c 41 89 44 24 0c 83 f9 04 7c ee } 		$a_01_1 = {8b 44 24 10 23 c7 01 44 24 14 d1 7c 24 10 83 7c 24 14 03 } 		$a_01_2 = {8b 44 8c 24 03 44 24 10 41 89 44 24 10 83 f9 03 7c ee } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}