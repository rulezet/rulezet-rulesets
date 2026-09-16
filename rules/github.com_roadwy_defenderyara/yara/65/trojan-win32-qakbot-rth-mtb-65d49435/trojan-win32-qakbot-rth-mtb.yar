rule Trojan_Win32_Qakbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 b8 93 29 8b 4c 24 ?? 8b 54 24 ?? 66 c7 44 24 ?? 92 a6 66 8b 74 24 ?? 6b c9 48 01 ca 89 54 24 ?? c7 84 24 ?? ?? ?? ?? a2 91 9f 8e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}