rule Trojan_Win32_Qakbot_GH_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 1c e4 29 db 09 c3 89 df 5b 89 55 f8 83 e2 00 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 8b 55 f8 83 fb 00 } 		$a_02_1 = {89 55 f8 83 e2 00 33 93 ?? ?? ?? ?? 83 e6 00 09 d6 8b 55 f8 6a 00 89 3c e4 31 ff 0b bb ?? ?? ?? ?? 89 f9 5f fc f3 a4 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}