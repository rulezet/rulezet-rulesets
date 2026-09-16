rule Trojan_Win32_Qakbot_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 3b bb fa ff 03 05 ?? ?? ?? ?? 8b 80 01 45 05 00 a3 } 		$a_02_1 = {03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? eb 98 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}