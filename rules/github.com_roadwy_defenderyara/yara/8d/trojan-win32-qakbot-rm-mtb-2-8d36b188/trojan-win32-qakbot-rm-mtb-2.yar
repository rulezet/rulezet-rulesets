rule Trojan_Win32_Qakbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 98 d9 0b 01 88 54 24 ?? 8a d3 2a d1 89 07 80 c2 13 a3 ?? ?? ?? ?? 0f b7 c9 83 c7 04 0f b6 c2 0f af c1 66 03 44 24 ?? 83 6c 24 ?? 01 0f b7 c8 89 ?? 24 4c 0f b7 c8 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}