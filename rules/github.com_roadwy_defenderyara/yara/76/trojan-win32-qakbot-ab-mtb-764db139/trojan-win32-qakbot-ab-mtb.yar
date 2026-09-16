rule Trojan_Win32_Qakbot_AB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d1 89 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 8a 4d ?? 88 08 e9 90 0a 30 00 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}