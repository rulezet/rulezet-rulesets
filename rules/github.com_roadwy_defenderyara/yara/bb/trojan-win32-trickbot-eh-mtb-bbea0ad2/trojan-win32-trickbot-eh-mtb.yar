rule Trojan_Win32_Trickbot_EH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d5 0f af d8 0f af d5 2b da 33 d2 8a 14 0f 83 eb 02 0f af d8 33 c0 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 03 da 2b dd 8b 2d ?? ?? ?? ?? 03 dd 8a 14 0b 8a 18 32 da 8b 54 24 ?? 88 18 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}