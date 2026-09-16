rule Trojan_Win32_Qakbot_GKM_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 } 		$a_02_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}