rule Trojan_Win32_Racealer_O_MTB_2{
	meta:
		description = "Trojan:Win32/Racealer.O!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3 } 		$a_01_1 = {8a 94 01 3b 2d 0b 00 88 14 30 40 3b c7 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}