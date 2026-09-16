rule Trojan_Win32_Qakbot_GE_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c9 83 c1 bb 8d 04 41 0f b7 c0 89 44 24 ?? 8b 02 05 a8 f8 02 01 89 02 83 c2 04 a3 ?? ?? ?? ?? 8b 44 24 ?? 83 c0 ?? 89 54 24 ?? 03 c1 83 6c 24 ?? 01 0f b6 c0 8d 04 c3 0f b7 f0 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}