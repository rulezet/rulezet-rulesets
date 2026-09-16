rule Trojan_Win32_Raccoon_RC_MTB_8{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 01 08 c3 } 		$a_03_1 = {ee 3d ea f4 89 45 [0-10] 33 75 ?? 31 75 [0-50] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 [0-10] d3 e8 [0-20] d3 e2 [0-08] 03 55 ?? 33 55 ?? 33 d6 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}