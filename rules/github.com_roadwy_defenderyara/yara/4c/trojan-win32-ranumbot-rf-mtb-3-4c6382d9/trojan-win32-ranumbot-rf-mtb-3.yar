rule Trojan_Win32_Ranumbot_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 83 3d ?? ?? ?? ?? 71 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}