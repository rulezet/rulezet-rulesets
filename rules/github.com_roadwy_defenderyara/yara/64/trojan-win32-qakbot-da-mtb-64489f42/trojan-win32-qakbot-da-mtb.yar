rule Trojan_Win32_Qakbot_DA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 83 e9 37 0f b7 45 f8 99 03 c8 88 4d ff 8b 15 ?? ?? ?? ?? 81 c2 d4 b4 08 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f4 8b 0d ?? ?? ?? ?? 89 88 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}