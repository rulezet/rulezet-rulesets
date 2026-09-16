rule Trojan_Win32_Dridex_AM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 6f 88 c1 80 c1 9d 88 4c 24 4f 88 c1 80 f1 e3 88 4c 24 55 } 		$a_01_1 = {88 44 24 33 89 d0 89 54 24 2c f7 e7 69 fe 6e c6 03 7a 01 fa 89 44 24 60 89 54 24 64 0f b6 c1 83 f8 6a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}