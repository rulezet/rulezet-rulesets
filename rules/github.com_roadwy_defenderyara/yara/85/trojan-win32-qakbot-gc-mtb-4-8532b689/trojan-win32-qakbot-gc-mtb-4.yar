rule Trojan_Win32_Qakbot_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 4d fc 31 c9 09 c1 89 8b ?? ?? ?? ?? 8b 4d fc 31 c9 8b 0c e4 83 c4 04 fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75 } 		$a_02_1 = {89 0c e4 ff b3 ?? ?? ?? ?? 59 01 c1 89 8b ?? ?? ?? ?? 59 ff a3 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}