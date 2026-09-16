rule Trojan_Win32_Ranumbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 8b 45 e4 50 8d ?? ec 51 e8 ?? ?? ?? ?? 8b ?? ?? 2b ?? ?? 89 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}