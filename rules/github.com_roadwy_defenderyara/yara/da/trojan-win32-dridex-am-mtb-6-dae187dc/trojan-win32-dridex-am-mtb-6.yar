rule Trojan_Win32_Dridex_AM_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c1 89 45 f4 8b 55 fc 8b 45 f0 8a 08 88 0a 8b 55 fc } 		$a_01_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 10 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}