rule Trojan_Win32_Qakbot_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 90 17 02 01 01 31 33 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 [0-05] a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}