rule Trojan_Win32_Raccoon_DE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 44 24 04 c2 04 00 81 00 dc 35 ef c6 c3 } 		$a_01_1 = {8b 4d f4 8b df d3 eb 03 5d dc 33 c3 89 45 ec 83 fa 27 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}