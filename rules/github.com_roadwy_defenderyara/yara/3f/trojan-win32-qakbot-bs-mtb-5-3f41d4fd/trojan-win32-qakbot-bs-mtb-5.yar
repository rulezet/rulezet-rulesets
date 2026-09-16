rule Trojan_Win32_Qakbot_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {01 fe 81 e6 ff 00 00 00 8b 7d ?? 8a 0c 37 8b 75 ?? 8b 7d ?? 32 0c 3e 8b 75 ?? 88 0c 3e 66 c7 45 ?? c5 b4 83 c7 01 8b 75 ?? 39 f7 } 		$a_02_1 = {89 14 24 8b 54 24 ?? 8a 0c 11 31 de 89 74 24 ?? 8b 74 24 ?? 8b 5c 24 ?? 32 0c 1e 8b 54 24 ?? 8b 74 24 ?? 88 0c 32 } 		$a_02_2 = {01 d8 8b 5c 24 ?? 8a 14 33 88 c6 0f b6 c6 8b 74 24 ?? 8a 34 06 30 d6 8b 44 24 ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 1c 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 88 34 38 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}