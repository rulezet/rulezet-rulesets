rule Trojan_Win32_Qakbot_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 68 d8 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 03 45 ?? 03 d8 6a 00 e8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}