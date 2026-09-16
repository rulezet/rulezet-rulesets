rule Trojan_Win32_Emotet_I_2{
	meta:
		description = "Trojan:Win32/Emotet.I,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c1 4a 3b 0d 40 20 47 00 75 1b 8b 15 08 20 47 00 83 c2 21 2b 15 40 20 47 00 } 		$a_01_1 = {89 0d 04 20 47 00 8b 15 08 20 47 00 69 d2 bb e3 00 00 2b 15 38 20 47 00 } 		$a_01_2 = {8b 15 04 20 47 00 69 d2 bb e3 00 00 2b 15 40 20 47 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}