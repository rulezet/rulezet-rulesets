rule Trojan_Win32_Qakbot_GD_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 83 e1 00 31 c1 83 a3 ?? ?? ?? ?? 00 09 8b ?? ?? ?? ?? 59 81 e1 00 00 00 00 8f 45 ?? 0b 4d ?? f3 a4 56 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75 ?? c7 45 ?? 00 00 00 00 ff 75 ?? 31 0c e4 50 8b 83 ?? ?? ?? ?? 87 04 e4 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}