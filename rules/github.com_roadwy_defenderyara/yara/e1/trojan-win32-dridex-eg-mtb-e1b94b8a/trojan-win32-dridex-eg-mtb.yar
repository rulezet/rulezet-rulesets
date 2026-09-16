rule Trojan_Win32_Dridex_EG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EG!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 14 f7 d7 8b 5c 24 20 f7 d3 89 5c 24 3c 89 7c 24 38 88 14 08 eb 0b } 		$a_01_1 = {8a 44 24 0b 24 3b 8b 4d 10 8b 54 24 2c 88 44 24 37 39 ca } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}