rule Trojan_Win32_Trickbot_BS_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 8b 51 ?? 8b 79 ?? 2b d7 03 d6 66 0f b6 0a 8b f9 2b c8 66 85 c9 7d ?? 81 c1 00 01 00 00 8b 85 ?? ?? ?? ?? 88 0a 03 f0 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}