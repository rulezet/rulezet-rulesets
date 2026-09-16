rule Trojan_Win32_Trickbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 e8 8d 44 6d ?? 2b d0 a1 ?? ?? ?? ?? 8b d8 0f af d8 8b c1 03 c2 8a 14 03 8b 44 24 ?? 8a 18 32 da 8b 54 24 ?? 88 18 8b 44 24 ?? 40 3b c2 89 44 24 ?? 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}