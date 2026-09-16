rule Trojan_Win32_Dridex_EM_MTB_7{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 38 8d 7f 01 4e 88 4f ff 8b c2 2b c6 2d 26 2c 00 00 } 		$a_01_1 = {02 c0 8d 8e 79 d3 ff ff 2a c4 02 c3 66 03 d9 8b 0c 2f 02 c0 81 c1 68 9c 02 01 66 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}