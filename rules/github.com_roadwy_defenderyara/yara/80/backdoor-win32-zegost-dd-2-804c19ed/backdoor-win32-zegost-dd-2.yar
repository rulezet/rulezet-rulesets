rule Backdoor_Win32_Zegost_DD_2{
	meta:
		description = "Backdoor:Win32/Zegost.DD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74 } 		$a_03_1 = {8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b ?? 7c } 		$a_03_2 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e } 		$a_01_3 = {55 c6 00 4d c6 40 01 5a 66 81 38 4d 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}