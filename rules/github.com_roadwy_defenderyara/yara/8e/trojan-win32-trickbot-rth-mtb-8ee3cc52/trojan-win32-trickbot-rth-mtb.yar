rule Trojan_Win32_Trickbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 83 ?? 20 33 d0 8b 4d ?? 88 11 8b 55 ?? 03 55 ?? 89 55 ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}