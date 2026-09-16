rule Trojan_Win32_Qakbot_GH_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 83 e6 00 09 c6 83 e7 00 31 f7 5e 52 33 14 ?? 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 5a 83 fb 00 ?? ?? 89 7d f8 89 df 03 bb ?? ?? ?? ?? 57 } 		$a_02_1 = {5e 89 55 f8 83 e2 00 0b 93 ?? ?? ?? ?? 83 e1 00 31 d1 8b 55 f8 fc f3 a4 50 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}