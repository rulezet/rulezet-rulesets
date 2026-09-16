rule Trojan_Win32_Qakbot_AD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 cb 6b d9 35 8b 4c 24 0c 2a 5c 24 10 8b 09 89 5c 24 18 81 c1 c4 5e 02 01 } 		$a_02_1 = {8b 5c 24 0c 83 44 24 0c 04 83 6c 24 14 01 89 0d ?? ?? ?? ?? 89 0b 8b 5c 24 18 0f b7 cf 89 4c 24 10 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}