rule Trojan_Win32_Trickbot_BS_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 89 84 9d ?? ?? ?? ?? 8b 84 8d ?? ?? ?? ?? 03 84 9d ?? ?? ?? ?? be e1 01 00 00 99 f7 fe 8a 84 95 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 30 04 32 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 } 		$a_00_1 = {5f 5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}