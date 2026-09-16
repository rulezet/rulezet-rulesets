rule Trojan_Win32_Dridex_ES_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.ES!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ca 8b 45 f0 6b c0 38 99 be 38 00 00 00 f7 fe 88 8c 05 f8 e1 ff ff 8b 45 f0 33 c9 8a 8c 05 f8 e1 ff ff 83 f9 05 } 		$a_01_1 = {8a 84 15 f8 e1 ff ff 83 e8 01 8b 4d f0 88 84 0d f8 e1 ff ff 8b 55 f0 83 c2 01 89 55 f0 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}