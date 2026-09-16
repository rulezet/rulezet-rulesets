rule Trojan_Win32_Qakbot_GJ_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 83 e8 5a 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 } 		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } 		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*20+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=31
 
}