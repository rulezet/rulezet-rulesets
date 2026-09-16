rule Trojan_Win32_Zbot_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 6b fa 03 00 01 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 0c 30 a1 ?? ?? ?? ?? 88 0c 30 46 8b 0d ?? ?? ?? ?? 3b f1 72 } 		$a_00_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3b 43 3b de 7c e7 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}