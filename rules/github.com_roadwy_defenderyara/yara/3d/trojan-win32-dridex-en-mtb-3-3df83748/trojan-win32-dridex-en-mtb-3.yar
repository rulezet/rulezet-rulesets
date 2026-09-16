rule Trojan_Win32_Dridex_EN_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 0b 83 c3 04 0f b6 c8 66 83 c1 49 89 5c 24 14 66 03 4c 24 28 83 6c 24 20 01 66 8b f9 89 7c 24 10 } 		$a_01_1 = {04 17 02 c0 02 c3 02 c1 02 c0 eb 07 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}