rule Trojan_Win32_Ranumbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? ?? 89 ?? ?? c7 [0-09] 8b 45 } 		$a_03_1 = {c1 e9 05 89 4d ?? 8b 45 ?? 01 45 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}