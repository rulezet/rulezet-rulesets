rule Trojan_Win32_Qakbot_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {49 8d 41 01 03 c7 a3 ?? ?? ?? ?? 8a 04 16 88 02 42 8b 1d ?? ?? ?? ?? 8b c3 2b c7 66 83 3d ?? ?? ?? ?? 00 8d 78 ?? 74 ?? b0 b9 2a c3 a2 ?? ?? ?? ?? 85 c9 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}