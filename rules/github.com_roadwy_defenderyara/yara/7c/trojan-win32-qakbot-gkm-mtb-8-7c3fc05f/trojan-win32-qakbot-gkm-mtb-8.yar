rule Trojan_Win32_Qakbot_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}