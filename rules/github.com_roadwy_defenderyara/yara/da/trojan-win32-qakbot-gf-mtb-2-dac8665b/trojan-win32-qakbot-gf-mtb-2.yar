rule Trojan_Win32_Qakbot_GF_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {3d c0 03 00 00 90 18 0f b7 c1 2b c2 83 c0 ?? 2b d8 83 df 00 8b 06 05 70 a0 07 01 89 06 83 c6 04 83 6c 24 ?? 01 a3 ?? ?? ?? ?? 8b 44 24 ?? 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}