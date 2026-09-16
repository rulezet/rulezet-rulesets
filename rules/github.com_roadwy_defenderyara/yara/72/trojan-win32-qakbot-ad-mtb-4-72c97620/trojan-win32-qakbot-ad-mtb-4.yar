rule Trojan_Win32_Qakbot_AD_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8d 0c 16 83 e0 ?? 8a 80 ?? ?? ?? ?? 32 04 0f 46 88 01 3b f3 72 ?? 5f 5e } 		$a_03_1 = {33 d2 8b c3 f7 75 ?? 8b 45 ?? 8a 04 02 32 04 0b 88 04 1f 43 83 ee 01 75 } 		$a_03_2 = {33 d2 8b c3 f7 f6 8b 45 ?? 8a 04 02 8b 55 ?? 32 04 13 8b 55 ?? 0f b6 c0 66 89 04 51 42 43 89 55 ?? 3b d7 72 } 		$a_03_3 = {8b c1 83 e0 ?? 8a 84 30 ?? 32 44 0e ?? 88 04 11 41 3b 0e 72 } 		$a_03_4 = {8b c7 83 e0 ?? 8a 44 05 ?? 32 04 37 88 44 3b ?? 47 3b 3b 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}