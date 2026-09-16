rule Trojan_Win32_Raccoon_AD_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00 } 		$a_01_1 = {c1 e8 05 05 12 c9 23 00 89 01 c3 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}