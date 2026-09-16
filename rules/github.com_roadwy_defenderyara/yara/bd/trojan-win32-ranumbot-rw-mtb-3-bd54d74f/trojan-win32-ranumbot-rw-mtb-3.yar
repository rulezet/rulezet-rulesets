rule Trojan_Win32_Ranumbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 44 24 ?? 03 ce 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}