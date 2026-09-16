rule Trojan_Win32_ShellCodeRunner_KK_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 23 6a 02 59 6b c9 2f 66 89 81 ?? ?? ?? ?? 6a 02 58 6b c0 2f 0f b7 80 ?? ?? ?? ?? 83 e8 07 6a 02 59 6b c9 30 } 		$a_01_1 = {79 79 78 66 5f 70 6c 61 79 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}