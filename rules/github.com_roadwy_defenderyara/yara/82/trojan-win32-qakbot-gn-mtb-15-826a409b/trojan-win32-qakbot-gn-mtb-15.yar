rule Trojan_Win32_Qakbot_GN_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 03 45 ?? 03 45 ?? 8b 55 ?? 31 [0-08] 8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-07] 2b d8 } 		$a_02_1 = {8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-07] 2b d8 89 5d ?? 8b 45 ?? 3b 45 } 		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}