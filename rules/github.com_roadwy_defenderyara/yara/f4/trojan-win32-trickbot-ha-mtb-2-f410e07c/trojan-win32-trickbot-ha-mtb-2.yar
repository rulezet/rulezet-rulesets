rule Trojan_Win32_TrickBot_HA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 12 33 db 43 2b df 0f af d8 8b 45 0c 89 4d f8 8b 0d ?? ?? ?? ?? 2b d9 6b c9 05 03 1d ?? ?? ?? ?? 03 5d fc 03 d8 8b 45 f4 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b d1 03 d7 03 15 ?? ?? ?? ?? 8a 04 32 30 03 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}