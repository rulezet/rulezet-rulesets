rule Trojan_Win32_Qakbot_GE_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 09 ce 59 89 7d ?? 83 e7 00 33 bb ?? ?? ?? ?? 83 e1 00 31 f9 8b 7d ?? fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 56 2b 34 e4 } 		$a_02_1 = {6a 00 89 14 e4 ff b3 ?? ?? ?? ?? 5a 01 c2 89 93 ?? ?? ?? ?? 5a ff a3 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}