rule Backdoor_Win32_Zegost_CI_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CI!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 } 		$a_03_1 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e } 		$a_03_2 = {8b 03 8b c8 8b d0 c1 e9 ?? c1 ea ?? 8b f0 83 e1 01 83 e2 01 c1 ee ?? a9 ?? ?? ?? ?? 74 15 } 		$a_01_3 = {56 57 8b 78 3c 89 65 f0 03 f8 89 7d e4 81 3f 50 45 00 00 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}