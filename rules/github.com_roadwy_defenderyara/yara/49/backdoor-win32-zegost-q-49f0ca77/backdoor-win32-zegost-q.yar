rule Backdoor_Win32_Zegost_Q{
	meta:
		description = "Backdoor:Win32/Zegost.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 be 0a 00 00 00 99 f7 fe 8a 82 ?? ?? ?? ?? 8a 91 ?? ?? ?? ?? 32 d0 88 91 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? 00 7c d9 } 		$a_01_1 = {25 73 5c 6d 74 25 78 6d 2e 64 6c 6c } 		$a_01_2 = {25 73 5c 6e 74 25 78 7a 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}