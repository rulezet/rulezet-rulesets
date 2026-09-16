rule Trojan_Win32_Qakbot_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 17 80 c1 21 0f b6 c1 3b 05 ?? ?? ?? ?? 8b 44 24 ?? 90 18 81 c2 b0 70 08 01 8a cd 02 0d ?? ?? ?? ?? 89 17 83 c7 04 ff 4c 24 ?? 89 15 ?? ?? ?? ?? 8b 54 24 ?? 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}