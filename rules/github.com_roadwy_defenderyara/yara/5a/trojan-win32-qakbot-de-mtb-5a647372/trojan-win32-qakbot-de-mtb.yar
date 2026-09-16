rule Trojan_Win32_Qakbot_DE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 3b c2 ?? ?? 2a 5c 24 0c 8b 06 2b 4c 24 14 05 94 d4 08 01 03 cf 89 06 a3 ?? ?? ?? ?? 83 c6 04 8a c1 89 0d ?? ?? ?? ?? 2a 44 24 0c 04 6f 83 6c 24 10 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}