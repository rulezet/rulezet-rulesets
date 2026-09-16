rule Trojan_Win32_Qakbot_EY_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EY!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c2 0f b6 cb 2b c8 83 c1 b4 03 f9 8b 4c 24 0c 8b 01 05 88 7f 03 01 89 01 83 c1 04 } 		$a_01_1 = {8a ca 02 4c 24 10 b0 f0 02 c9 2a c1 8b ce 02 d8 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}