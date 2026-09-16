rule Trojan_Win32_Raccoon_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 11 c3 cc [0-15] 81 01 e1 34 ef c6 c3 } 		$a_01_1 = {01 44 24 20 8b 44 24 20 89 44 24 28 8b 44 24 18 8b 4c 24 1c d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 33 c1 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}