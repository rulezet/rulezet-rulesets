rule Trojan_Win32_Ranumbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 4c 24 ?? 8d 0c 32 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}