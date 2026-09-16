rule Backdoor_Win32_Zegost_Q_2{
	meta:
		description = "Backdoor:Win32/Zegost.Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {25 2d 32 34 73 20 25 2d 31 35 73 } 		$a_03_1 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? 00 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5 85 c0 7e ?? 8d 8c 24 90 1b 00 00 00 50 51 } 		$a_03_2 = {57 50 ff b6 ?? 00 00 00 ff 15 ?? ?? ?? ?? 80 bd ?? ?? ff ff 05 0f 85 ?? ?? 00 00 38 9d ?? ?? ff ff 74 0d 80 bd 90 1b 04 ff ff 02 0f 85 ?? ?? 00 00 80 bd 90 1b 04 ff ff 02 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 59 0f 86 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}