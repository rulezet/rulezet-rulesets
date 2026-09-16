rule Trojan_Win32_Qakbot_GI_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {31 18 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 90 0a 5a 00 03 d8 [0-07] 2b d8 [0-07] 03 d8 [0-07] 2b d8 } 		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}