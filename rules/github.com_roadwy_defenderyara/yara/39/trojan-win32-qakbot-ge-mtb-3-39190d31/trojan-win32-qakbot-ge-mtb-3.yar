rule Trojan_Win32_Qakbot_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 66 03 c6 66 89 44 24 ?? 0f b7 f0 8b 01 05 e8 66 03 01 89 01 8a cb a3 ?? ?? ?? ?? 80 e9 ?? 66 8b 44 24 ?? 02 c8 83 6c 24 ?? 01 88 4c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}