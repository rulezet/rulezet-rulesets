rule Trojan_Win32_Trickbot_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 c7 45 ?? 00 00 00 00 eb ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 74 ?? 8b 45 ?? 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 32 04 11 8b 4d ?? 03 4d ?? 88 01 eb } 		$a_02_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-40] 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}