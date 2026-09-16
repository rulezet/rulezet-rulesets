rule Trojan_Win32_Qakbot_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 da 2b d8 83 c3 01 89 1d ?? ?? ?? ?? 8a c1 b3 ?? f6 eb 2a c2 8a d0 83 7c 24 ?? 00 75 } 		$a_02_1 = {8b cb 6b c9 ?? 2b c8 2b c8 8d 4c 19 01 8b 6c 24 ?? 6b c0 ?? 81 c6 ?? ?? ?? ?? 2b c7 89 75 00 03 c2 83 c5 04 83 6c 24 ?? 01 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}