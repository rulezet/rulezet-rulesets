rule Trojan_Win32_Qakbot_BH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7d e4 89 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}