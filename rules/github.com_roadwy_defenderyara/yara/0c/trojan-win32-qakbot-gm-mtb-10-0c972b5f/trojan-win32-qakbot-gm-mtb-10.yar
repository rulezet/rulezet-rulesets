rule Trojan_Win32_Qakbot_GM_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 83 c0 04 03 d8 [0-08] 2b d8 89 5d ?? 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 90 0a 4b 00 8b 45 ?? 03 45 ?? 8b 55 ?? 31 } 		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}