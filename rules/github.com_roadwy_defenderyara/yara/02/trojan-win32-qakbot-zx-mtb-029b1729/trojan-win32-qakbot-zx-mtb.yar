rule Trojan_Win32_Qakbot_ZX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 59 8b 4d f8 3b 0d ?? ?? ?? ?? 72 02 eb 4c 8b 45 f8 33 d2 b9 ?? ?? 00 00 f7 f1 85 d2 75 0e } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}