rule Trojan_Win32_Qakbot_EY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}