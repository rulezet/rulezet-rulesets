rule Trojan_Win32_Dridex_QW_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c0 2b c7 83 ea 02 05 e1 95 ff ff 03 c3 83 fa 02 7f e7 } 		$a_01_1 = {02 d1 8a c2 2c 2d 0f b6 c0 6a 0a 89 44 24 10 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}