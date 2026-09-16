rule Trojan_Win32_Qakbot_GJ_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 cc 03 45 ac 2d f2 05 00 00 03 45 a0 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 } 		$a_02_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 90 0a 14 00 99 52 50 } 		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}